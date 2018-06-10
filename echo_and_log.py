#!/usr/bin/env python3

import argparse
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

ASCII_WHITE_LIST = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+[]{}:;\"'\\|,.<>/?`~ "


logger = logging.getLogger("echo_and_log")




# From https://stackoverflow.com/questions/2699907/dropping-root-permissions-in-python
def drop_privileges(uid_name='nobody', gid_name='nogroup'):

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
    """
    :returns socket:
    """
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(10)
    return s

def start_listen_socks(port_list):
    """
    :returns list of tuples: [(listening socket, port), ...]
    """
    return [(start_listen_sock(port), port) for port in port_list]


class ClientList(list):
    """
    Maintain clients, take actions affecting all clients
    """
    def __init__(self, listen_socks):
        """
        :param list listen_socks: A list containing listening sockets
        """
        self.listen_socks = listen_socks

    def run_time_step(self):
        self.look_for_new_clients()
        self.echo_and_log()
        self.age_clients()
        self.remove_dead_clients()

    def look_for_new_clients(self):
        """
        Look, across all listening sockets, to find a connection request
        Does not block
        """
        sock_dict = {sock[0]: sock for sock in self.listen_socks}
        rdy, _, _ = select.select(sock_dict.keys(), [], [], 0)
        self.extend(Client(sock_dict[rdy_sock]) for rdy_sock in rdy)

    def echo_and_log(self):
        """
        Look, across all clients, to find data available for reading
        When data is found, echo it back and store it for logging
        """
        socks = {client.sock: client for client in self}
        can_recv, can_send, _ = select.select(socks.keys(), socks.keys(), 
                [], 0)
        for sock in can_recv:
            socks[sock].handle_data(sock in can_send)

    def age_clients(self):
        """
        Increase all clients' ages
        """
        _ = [client.inc_age() for client in self]

    def remove_dead_clients(self):
        """
        Replace the list with one containing only alive clients
        """
        self[:] = [client for client in self if not client.dead]


class Client:
    """
    Handle all requirements for a connected client
    """
    def __init__(self, listen_sock_and_port):
        """
        Accept a connection on listen_sock, and become a new client
        """
        self.listen_sock = listen_sock_and_port[0]
        self.listen_port = listen_sock_and_port[1]
        self.sock, client_conn = self.listen_sock.accept()
        self.client_addr = client_conn[0]
        self.client_port = client_conn[1]
        self.data = b""
        self.age = 0
        self.dead = False
    
    def inc_age(self):
        """
        Increase the client's age, and kill it if it's too old
        """
        self.age += 1
        if self.age > CLIENT_AGE_OUT:
            self.die()

    def die(self):
        """
        Handle the client's death nicely - close the socket and emit logs
        """
        self.sock.close()
        self.dead = True
        self.write_log()

    def write_log(self):
        """
        Emit one consolidated log entry for the client
        """
        white_list = [ord(i) for i in ASCII_WHITE_LIST]
        filt_dat = [(chr(c) if c in white_list else ".") for c in self.data]
        ascii_friendly_data = "".join(filt_dat)

        log_dict = {
                "client_addr": self.client_addr,
                "client_port": self.client_port,
                "server_port": self.listen_port,
                "closed_early": self.age <= CLIENT_AGE_OUT,
                "data_hex": binascii.hexlify(self.data).decode("ascii"),
                "data_ascii": ascii_friendly_data,
                "data_xxd": hex_fmt_data(self.data, "\n"),
                }

        str_fmt = "{}:{}->local:{} {}{}".format(
                log_dict["client_addr"],
                log_dict["client_port"],
                log_dict["server_port"],
                "closed early " if log_dict["closed_early"] else "",
                log_dict["data_xxd"]
                )

        logger.info(str_fmt)

    def close_early(self):
        """
        Handle when the client closed earlier than age-related death
        """
        self.die()

    def handle_data(self, try_send):
        """
        Assumes data is available for read!  Don't call on dead clients...
        :param bool try_send:
            If true, try to send data.  If you want to avoid blocking, set
            this parameter based on the output of a select statement
        """
        if self.dead:
            raise RuntimeError("Tried to handle data on dead client")

        try:
            dat = self.sock.recv(1024)
        except ConnectionResetError as e:
            self.close_early()
            return

        if dat == b"":
            self.close_early()
            return

        self.data += dat

        if try_send:
            try:
                self.sock.send(dat)
            except ConnectionResetError as e:
                self.close_early()
                return
        
        return

def hex_fmt_data(data, separator="     "):
    """
    Format data into an xxd-like representation for logging
    """
    white_list = [ord(i) for i in ASCII_WHITE_LIST]
    seg_length = 16

    ret = ""
    for ind in range(0, len(data), seg_length):
        dat_seg = data[ind:ind+seg_length]
        bin_asc = binascii.hexlify(dat_seg).decode("ascii")
        filtered_dat = [(chr(c) if c in white_list else ".") for c in dat_seg]
        filt_txt = "".join(filtered_dat)
        ret += "{}{} {}".format(separator, bin_asc, filt_txt) 
    return ret


def main_loop(port_list):
    """
    The main loop for execution - ends with an exception (including Ctrl+C)
    :param list port_list: A list of integers of ports to listen on
    """
    listen_sock_list = start_listen_socks(port_list)
    drop_privileges()
    client_list = ClientList(listen_sock_list)
    while True:
        client_list.run_time_step()
        time.sleep(LOOP_PERIOD)



def port_list_type(str_input):
    try:
        return {int(i.strip(), 0) for i in str_input.split(",")}
    except:
        raise argparse.ArgumentTypeError(
                "Port list must consist of integers separated by commas")

if __name__ == "__main__":
    port_list = \
            "69,445,8545,3389,2323,5555,5060,6379,2004,81,8888,123,3392"

    parser = argparse.ArgumentParser(description=
            "Listen to ports, echo and log the data received at them")
    parser.add_argument("-p", "--port-list", type=port_list_type,
            help="A comma-separated list of integers for ports to listen to",
            default=port_list)
    args = parser.parse_args()

    logger.addHandler(logging.StreamHandler())
    #logger.addHandler(logging.handlers.SysLogHandler(address="/dev/log"))

    handler = logging.handlers.SysLogHandler(address="/dev/log")
    handler.setFormatter(logging.Formatter("ECHO_AND_LOG: %(message)s"))
    logger.addHandler(handler)

    logger.setLevel(logging.INFO)

    main_loop(args.port_list)
