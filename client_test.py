#!/usr/bin/python3

import socket, sys, subprocess, array, struct, os, traceback
m_socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
m_socket.connect(sys.argv[1])
m_socket.send(b'\1\0\0\0' + struct.pack(">I", int(sys.argv[2])))

g_msg = m_socket.recv(4)

while True:
    first_fd = -1
    try:
        new_msg, anc_data, flags, address = m_socket.recvmsg(128, 4096)
        if len(new_msg) == 0:
            break
        for cmsg_level, cmsg_type, cmsg_data in anc_data:
            if (cmsg_level == socket.SOL_SOCKET) and (cmsg_type == socket.SCM_RIGHTS):
                sock_list = list(array.array("i", cmsg_data[:len(cmsg_data) & 0xfffffffc]))
                for fd in sock_list:
                    if first_fd == -1:
                        first_fd = fd
                    else:
                        os.close(fd)

        if first_fd >= 0:
            subprocess.Popen(sys.argv[3:], stdin=first_fd, stdout=first_fd)
    except:
        traceback.print_exc(file=sys.stderr)
        pass
    finally:
        if first_fd >= 0:
            os.close(first_fd)
