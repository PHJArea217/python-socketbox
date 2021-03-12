#!/usr/bin/python3
import os, socket, selectors, traceback, sys, struct, signal
event_loop = selectors.DefaultSelector()
signal.signal(signal.SIGPIPE, signal.SIG_IGN)
import socketbox_init

for s in socketbox_init.incoming_sockets:
    event_loop.register(s.sock_object, selectors.EVENT_READ, (1, s))

for s in socketbox_init.api_sockets:
    event_loop.register(s.sock_object, selectors.EVENT_READ, (2, s))

while True:
    select_events = event_loop.select()
    for e, m in select_events:
        event_type, event_arg = e.data
        if event_type == 2:
            for _unused in range(1, 20):
                need_dec = False
                sock_uid = -1
                try:
                    api_connection_socket, r_addr = event_arg.sock_object.accept()
                    api_connection_socket.setblocking(False)
                    sock_uid = socketbox_init.socketbox_typedefs.get_sock_uid(api_connection_socket)
                    if not sock_uid in socketbox_init.permitted_uids:
                        api_connection_socket.close()
                        continue
                    if socketbox_init.permitted_uids[sock_uid].increment() != 1:
                        api_connection_socket.close()
                        continue
                    need_dec = True
                    event_loop.register(api_connection_socket, selectors.EVENT_READ,
                            (3, socketbox_init.socketbox_typedefs.SocketboxConnection(api_connection_socket, sock_uid, event_arg.index)))
                except:
#                    traceback.print_exc(file=sys.stderr)
                    if need_dec:
                        socketbox_init.permitted_uids[sock_uid].decrement()
                    break
        elif event_type == 1:
            for _unused in range(1, 20):
                fwd_socket = None
                try:
                    fwd_socket, r_addrf = event_arg.sock_object.accept()
                    r_addr, r_port, _n1, _n2 = r_addrf
                    l_addr, l_port, _n1, _n2 = fwd_socket.getsockname()
                    rule_s = {"l_ip": l_addr, "l_port": l_port, "r_ip": r_addr, "r_port": r_port, "incoming_socket": event_arg.index}
                    rule_c, _unused2 = socketbox_init.socketbox_typedefs.rule_canon(rule_s)
                    current_rule = socketbox_init.rules["_start"]
                    found_target = None
                    for _unused3 in range(1, 100):
                        if isinstance(current_rule, socketbox_init.socketbox_typedefs.SocketboxMap):
                            reduced_rule_c = bytes(i & j for i, j in zip(rule_c, current_rule.mask))
                            rule_disposition = current_rule.rules[reduced_rule_c] # This may often fail!
                            if rule_disposition.action_type == 1:
                                current_rule = socketbox_init.rules[rule_disposition.action_arg]
                            else:
                                found_target = rule_disposition.action_arg
                                break
                        else:
                            for rule in current_rule.rules_list:
                                reduced_rule_c = bytes(i & j for i, j in zip(rule_c, rule.match.mask_b))
                                if rule.match.match_b == reduced_rule_c: 
                                    if rule.action_type == 1:
                                        current_rule = socketbox_init.rules[rule.action_arg]
                                        break
                                    else:
                                        found_target = rule.action_arg
                                        break
                            if found_target != None:
                                break
                    if isinstance(found_target, socketbox_init.socketbox_typedefs.SocketboxRegistrationSlot):
                        target_a = found_target
                        socketbox_init.socketbox_typedefs.send_socket(target_a.registered_socket, fwd_socket) # Fails if no registered socket
                except:
#                    traceback.print_exc(file=sys.stderr)
                    if fwd_socket != None:
                        fwd_socket.close()
                    fwd_socket = None
                    break
                finally:
                    if fwd_socket != None:
                        fwd_socket.close()
        elif event_type == 3:
            try:
                i_packet = event_arg.socket_file.recv(4096)
                if event_arg.has_received_msg:
                    raise OSError
                if len(i_packet) != 8:
                    raise OSError

                i_packet_cmd = i_packet[0]
                i_packet_reserved_1 = i_packet[1]
                i_packet_reserved_2, = struct.unpack(">H", i_packet[2:4])
                i_packet_slot, = struct.unpack(">I", i_packet[4:8])

                if (i_packet_reserved_1 != 0) or (i_packet_reserved_2 != 0):
                    raise OSError

                if i_packet_cmd == 1:
                    conn_slot = socketbox_init.registration_slots[i_packet_slot] # may fail with exception
                    if (conn_slot.auth_data.uid == event_arg.uid) and (conn_slot.auth_data.socket_nr == event_arg.orig_socket_nr) and (conn_slot.registered_socket == None):
                        conn_slot.registered_socket = event_arg.socket_file
                        event_arg.has_received_msg = True
                        event_arg.reg_slot = conn_slot
                        event_arg.socket_file.send(b'\200\0\0\0')
                    else:
                        raise OSError
            except:
                if event_arg.reg_slot != None:
                    event_arg.reg_slot.registered_socket = None
                socketbox_init.permitted_uids[event_arg.uid].decrement()
                event_loop.unregister(event_arg.socket_file)
                event_arg.socket_file.close()
