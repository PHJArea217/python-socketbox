#!/usr/bin/python3

import sys, json, socket, os, socketbox_typedefs
if len(sys.argv) != 2:
    sys.stderr.write("Usage: socketbox_init.py [config.json]\n")
    sys.exit(1)

config_json = json.load(open(sys.argv[1], "r"))

if config_json['socketbox-version'] != 1:
    sys.stderr.write("Only version 1 supported right now\n")
    sys.exit(2)

incoming_sockets = []
_index = 0
for i in config_json['incoming']:
    if "fd" in i:
        i_socket = socket.socket(fileno=i['fd'])
        if i.get("listen", False) == True:
            i_socket.listen(i.get("backlog", 4096))
    else:
        if "netns" in i:
            socketbox_typedefs.change_netns(i['netns'])
        i_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        if i.get("transparent", False) == True:
            i_socket.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
        if i.get("freebind", False) == True:
            i_socket.setsockopt(socket.SOL_IP, socket.IP_FREEBIND, 1)
        if i.get("reuseaddr", True) == True:
            i_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if i.get("reuseport", False) == True:
            i_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        i_socket.bind((i['address'], i['port']))
        i_socket.listen(i.get("backlog", 4096))
    i_socket.setblocking(False)
    incoming_sockets.append(socketbox_typedefs.SocketboxIncomingSocket(sock_object=i_socket, index=_index))
    _index = _index + 1

daemon_args = config_json['daemon']

if "final_netns" in config_json:
    socketbox_typedefs.change_netns(config_json['final_netns'])

api_sockets = []
_index = 0
for path in config_json['paths']:
    t_socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    t_socket.setblocking(False)
    socket_uid = path.get('uid', -1)
    socket_gid = path.get('gid', -1)
    socket_path = path['socket']
    if len(socket_path) > 90:
        raise OSError("socket path must be less than 90 chars long")
    socket_mode = int(path.get('mode', "700"), base=8)
    try:
        os.unlink(socket_path)
    except:
        pass
    old_umask = os.umask(0o077)
    t_socket.bind(socket_path)
    os.umask(old_umask)
    t_socket.listen()
    os.chown(socket_path, socket_uid, socket_gid)
    os.chmod(socket_path, socket_mode)
    api_sockets.append(socketbox_typedefs.SocketboxAPISocket(sock_object=t_socket, index=_index))
    _index = _index + 1

if "chroot" in daemon_args:
    os.chroot(daemon_args['chroot'])
    os.chdir("/")

if "groups" in daemon_args:
    os.setgroups(daemon_args['groups'])

if "gid" in daemon_args:
    os.setgid(daemon_args['gid'])

if "uid" in daemon_args:
    os.setuid(daemon_args['uid'])

registration_slots = []
permitted_uids = {}

for slot in config_json['outgoing']:
    uid_nr = int(slot['uid'])
    registration_slots.append(socketbox_typedefs.SocketboxRegistrationSlot(socketbox_typedefs.SocketboxClientAuthData(uid=uid_nr, socket_nr=int(slot['path_nr']))))
    permitted_uids[uid_nr] = socketbox_typedefs.SocketboxCounter(5) # TODO make this customizable, also account for the presence of multiple API sockets

rules = {}
rule_list = config_json['rules']
for rule in rule_list:
    my_data = rule_list[rule]
    my_elem = None
    t = my_data['type']
    is_map = False
    map_mask = b'\0\0\0\0' + (b'\377' * 18) + (b'\0' * 18)
    if t == 'rule':
        my_elem = socketbox_typedefs.SocketboxRuleList(rules_list=[])
    elif t == 'map':
        is_map = True
        if 'mask' in my_data:
            map_mask = socketbox_typedefs.rule_canon(my_data['mask']).mask_b
            my_elem = socketbox_typedefs.SocketboxMap(mask=map_mask, rules={})
        else:
            my_elem = socketbox_typedefs.SocketboxMap(mask=map_mask, rules={})
    else:
        raise OSError("Rule list type must be 'rule' or 'map'")
    for r in my_data['rules']:
        jump_target = str(r['jump'])
        if jump_target[1] != ':':
            raise OSError("Jump target must be of the form [or]:[target]")
        key_t = jump_target[0]
        key_v = jump_target[2:]
        if key_t == 'r':
            jump_type = 1
            jump_value = key_v
        elif key_t == 'o':
            jump_type = 2
            jump_value = registration_slots[int(key_v)]
        else:
            raise OSError("Type of jump must be 'o' or 'r'")
        if is_map:
            match_val = socketbox_typedefs.rule_canon(r)
            map_key = bytes(i & j for i, j in zip(match_val.match_b, map_mask))
            my_elem.rules[map_key] = socketbox_typedefs.SocketboxRule(match=None, action_type=jump_type, action_arg=jump_value)
        else:
            my_elem.rules_list.append(socketbox_typedefs.SocketboxRule(match=socketbox_typedefs.rule_canon(r), action_type=jump_type, action_arg=jump_value))
    rules[rule] = my_elem

if not "_start" in rules:
    raise OSError("No _start rule found")
