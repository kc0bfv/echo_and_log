#!/usr/bin/env python3

import binascii
import itertools
import logging
import logging.handlers
import select
import socket
import syslog
import time

import grp
import os
import pwd

# Number of loops clients should remain, max
CLIENT_AGE_OUT = 10
# Number of seconds each loop takes
LOOP_PERIOD = 1

logger = logging.getLogger("echo_and_log")

def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    # From https://stackoverflow.com/questions/2699907/dropping-root-permissions-in-python
    if os.getuid() != 0:
        # We're not root so, like, whatever dude
        return

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

    # Ensure a very conservative umask
    old_umask = os.umask(0o77)

def start_listen_sock(port, addr="0.0.0.0"):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(10)
    return s

def start_listen_socks(port_list):
    return [(start_listen_sock(port), port) for port in port_list]

def look_for_connect_request(listen_sock_list):
    sock_dict = {sock[0]: sock for sock in listen_sock_list}
    rdy, _, _ = select.select(sock_dict.keys(), [], [], 0)
    new_clients = [(rdy_sock.accept(), sock_dict[rdy_sock][1])
            for rdy_sock in rdy]
    fixed_new = [(sock, client_addr, port) 
            for ((sock, client_addr), port) in new_clients]
    for client in fixed_new:
        log_new_client(client)
    return fixed_new

def look_for_client_data(clients):
    """
    Only expect to be able to iterate over clients once...
    """
    client_dict = {client[0]: client for client in clients}
    rdy, _, _ = select.select(client_dict.keys(), [], [], 0)
    _, can_send, _ = select.select([], client_dict.keys(), [], 0)
    for rdy_sock in rdy:
        try:
            dat = rdy_sock.recv(1024)
        except ConnectionResetError as e:
            log_conn_reset(client_dict[rdy_sock])
        else:
            if dat != b"":
                log_data(client_dict[rdy_sock], dat)
                if rdy_sock in can_send:
                    try:
                        rdy_sock.send(dat)
                    except ConnectionResetError as e:
                        log_conn_reset(client_dict[rdy_sock])
            else:
                log_closed_early(client_dict[rdy_sock])

def close_clients(clients):
    """
    Only expect to be able to iterate over clients once...
    """
    for client in clients:
        client[0].close()
        log_close_client(client)

def hex_fmt_data(data):
    char_white_list = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+[]{}:;\"'\\|,.<>/?`~ "
    white_list = [ord(i) for i in char_white_list]
    seg_length = 16

    ret = ""
    for ind in range(0, len(data), seg_length):
        dat_seg = data[ind:ind+seg_length]
        bin_asc = binascii.hexlify(dat_seg).decode("ascii")
        filtered_dat = [(chr(c) if c in white_list else ".") for c in dat_seg]
        filt_txt = "".join(filtered_dat)
        ret += "     {} {}".format(bin_asc, filt_txt) 
    return ret

def fmt_client(client):
    addr = client[1]
    return "{}:{}->local:{}".format(addr[0], addr[1], client[2])

def log_data(client, data):
    data_fmt = hex_fmt_data(data)
    logger.info("Client {} - data:{}".format(fmt_client(client), data_fmt))

def log_new_client(client):
    logger.info("New client {}".format(fmt_client(client)))

def log_closed_early(client):
    logger.info("Client {} - closed early".format(fmt_client(client)))

def log_conn_reset(client):
    logger.info("Client {} - connection reset".format(fmt_client(client)))

def log_close_client(client):
    logger.info("Closed client {}".format(fmt_client(client)))

def main_loop(port_list):
    listen_sock_list = start_listen_socks(port_list)
    drop_privileges()

    # client_list will become a list of lists, max length CLIENT_AGE_OUT
    client_list = list()

    while True:
        new_clients = look_for_connect_request(listen_sock_list)
        client_list.insert(0, new_clients)
        if len(client_list) > CLIENT_AGE_OUT:
            age_off = itertools.chain(*client_list[CLIENT_AGE_OUT:])
            close_clients(age_off)
            client_list = client_list[:CLIENT_AGE_OUT]

        look_for_client_data(itertools.chain(*client_list))

        time.sleep(LOOP_PERIOD)

if __name__ == "__main__":
    port_list = {69, 445, 8545, 3389, 2323, 5555, 5060, 6379, 2004,
            81, 8888, 123, 3392}

    logger.addHandler(logging.StreamHandler())
    #logger.addHandler(logging.handlers.SysLogHandler(address="/dev/log"))

    handler = logging.handlers.SysLogHandler(address="/dev/log")
    handler.setFormatter(logging.Formatter("ECHO_AND_LOG: %(message)s"))
    logger.addHandler(handler)

    logger.setLevel(logging.INFO)

    main_loop(port_list)
