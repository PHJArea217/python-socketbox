#!/usr/bin/python3

import collections, socket, struct, os, ctypes

SocketboxRuleList = collections.namedtuple('SocketboxRuleList', ['rules_list'])
SocketboxMap = collections.namedtuple('SocketboxMap', ['mask', 'rules'])
SocketboxRule = collections.namedtuple('SocketboxRule', ['match', 'action_type', 'action_arg'])

SocketboxClientAuthData = collections.namedtuple('SocketboxClientAuthData', ['uid', 'socket_nr'])

SocketboxIncomingSocket = collections.namedtuple('SocketboxIncomingSocket', ['sock_object', 'index'])
SocketboxTarget = collections.namedtuple('SocketboxTarget', ['sock_object', 'uid', 'orig_socket_nr'])
SocketboxAPISocket = collections.namedtuple('SocketboxAPISocket', ['sock_object', 'index'])

SocketboxRuleCanonical = collections.namedtuple('SocketboxRuleCanonical', ['match_b', 'mask_b'])

class SocketboxRegistrationSlot:
    def __init__(self, auth_data):
        self.auth_data = auth_data
        self.registered_socket = None

class SocketboxConnection:
    def __init__(self, socket_file, uid, orig_socket_nr):
        self.socket_file = socket_file
        self.uid = uid
        self.orig_socket_nr = orig_socket_nr
        self.has_received_msg = False
        self.reg_slot = None

class SocketboxCounter:
    def __init__(self, maximum):
        self.current = 0
        self.maximum = int(maximum)
    def increment(self):
        if self.current >= self.maximum:
            return 0
        self.current = self.current + 1
        return 1
    def decrement(self):
        if self.current < 0:
            return 0
        self.current = self.current - 1
        return 1

def get_sock_uid(_socket):
    ucred = _socket.getsockopt(socket.SOL_SOCKET, 17, 12)
    uid, = struct.unpack("=I", ucred[4:8])
    return uid

def rule_canon(rule):
    # TODO: support CIDR notation
    if 'l_ip' in rule:
        l_ip = socket.inet_pton(socket.AF_INET6, rule['l_ip'])
        l_mask = socket.inet_pton(socket.AF_INET6, rule.get('l_mask', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))
        l_ip = bytes(i & j for i, j in zip(l_ip, l_mask))
    else:
        l_ip = b'\0' * 16
        l_mask = b'\0' * 16
    
    if len(l_ip) != 16:
        raise OSError

    if 'r_ip' in rule:
        r_ip = socket.inet_pton(socket.AF_INET6, rule['r_ip'])
        r_mask = socket.inet_pton(socket.AF_INET6, rule.get('r_mask', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))
        r_ip = bytes(i & j for i, j in zip(r_ip, r_mask))
    else:
        r_ip = b'\0' * 16
        r_mask = b'\0' * 16
    
    if len(r_ip) != 16:
        raise OSError

    if 'l_port' in rule:
        l_port = struct.pack(">H", int(rule['l_port']))
        l_port_mask = b'\377\377'
    else:
        l_port = b'\0\0'
        l_port_mask = b'\0\0'

    if 'r_port' in rule:
        r_port = struct.pack(">H", int(rule['r_port']))
        r_port_mask = b'\377\377'
    else:
        r_port = b'\0\0'
        r_port_mask = b'\0\0'

    if 'incoming_socket' in rule:
        path_m = struct.pack(">I", int(rule['incoming_socket']))
        path_m_mask = b'\377\377\377\377'
    else:
        path_m = b'\0\0\0\0'
        path_m_mask = b'\0\0\0\0'

    match_data = path_m + l_ip + l_port + r_ip + r_port
    match_mask = path_m_mask + l_mask + l_port_mask + r_mask + r_port_mask
    return SocketboxRuleCanonical(match_b=match_data, mask_b=match_mask)

__libc = ctypes.CDLL(None)
__setns = __libc.setns
__setns.argtypes = [ctypes.c_int, ctypes.c_int]
def change_netns(netns_file):
    _fd = os.open(netns_file, os.O_RDONLY)
    if not (__setns(_fd, 0x40000000) == 0):
        raise OSError("Failed to setns")
    os.close(_fd)

def send_socket(target, fd):
    target.sendmsg([b'\3\0\0\0'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('=I', fd.fileno()))], socket.MSG_NOSIGNAL)
