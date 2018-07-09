#!/usr/bin/env python3

import argparse
import binascii
import itertools
import logging
import logging.handlers
import logstash
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

LOGSTASH_HOST = "localhost"
LOGSTASH_PORT = 5959

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


class ListenList(list):
    def __init__(self, port_list):
        tcp_socks = [ListenSockTCP(port) for port in port_list]
        udp_socks = [ListenSockUDP(port) for port in port_list]
        self[:] = tcp_socks + udp_socks

class ListenSock:
    sock_type = None
    def __init__(self, port, addr="0.0.0.0"):
        self.port = port
        self.addr = addr
        self.sock = socket.socket(type=self.sock_type)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.addr, self.port))

    def handle_recv(self):
        """
        Handle whatever's necessary for this sock_type when data
        is available to recv - on TCP, accept a connection, on UDP, recv data
        """
        raise RuntimeError("Called handle_recv on parent ListenSock class")

class ListenSockTCP(ListenSock):
    sock_type = socket.SOCK_STREAM
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sock.listen(10)

    def handle_recv(self):
        """
        Return a client for a connection
        """
        return ClientTCP(self)

class ListenSockUDP(ListenSock):
    sock_type = socket.SOCK_DGRAM
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def handle_recv(self):
        """
        This happens when there's data available to read, with UDP
        Go ahead and handle it
        :returns None:
        """
        ClientUDP(self)
        return None




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
        self.handle_new_clients()
        self.echo_and_log()
        self.age_clients()
        self.remove_dead_clients()

    def handle_new_clients(self):
        """
        Look, across all server sockets, to find a connection request (TCP)
        or data available to read (in the case of UDP)
        Does not block
        """
        sock_dict = {listener.sock: listener for listener in self.listen_socks}
        rdy, _, _ = select.select(sock_dict.keys(), [], [], 0)
        new_clients = (sock_dict[rdy_sock].handle_recv() for rdy_sock in rdy)
        self.extend(client for client in new_clients if client is not None)

    def echo_and_log(self):
        """
        Look, across connection-oriented clients, to find data available for 
        reading.  When data is found, echo it back and store it for logging.
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
    Handle all requirements for a connected client, whether UDP or TCP
    """
    server_type = None
    def __init__(self, listen_sock):
        self.listen_sock = listen_sock
        self.age = 0
        self.closed_early = False

    def hex_fmt_data(self, separator="\n"):
        """
        Format data into an xxd-like representation for logging
        """
        white_list = [ord(i) for i in ASCII_WHITE_LIST]
        seg_length = 16

        ret = ""
        for ind in range(0, len(self.data), seg_length):
            dat_seg = self.data[ind:ind+seg_length]
            bin_asc = binascii.hexlify(dat_seg).decode("ascii")
            filtered_dat = [(chr(c) if c in white_list else ".") for c in dat_seg]
            filt_txt = "".join(filtered_dat)
            ret += "{}{} {}".format(separator, bin_asc, filt_txt) 
        return ret

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
                "server_port": self.listen_sock.port,
                "server_type": self.server_type,
                "closed_early": self.closed_early,
                "data_hex": binascii.hexlify(self.data).decode("ascii"),
                "data_ascii": ascii_friendly_data,
                "data_xxd": self.hex_fmt_data(),
                }

        str_fmt = "{}:{}->local:{} {} {}{}".format(
                log_dict["client_addr"],
                log_dict["client_port"],
                log_dict["server_port"],
                log_dict["server_type"],
                "closed early " if log_dict["closed_early"] else "",
                self.hex_fmt_data("     "),
                )

        logger.info(str_fmt, extra = log_dict)

class ClientUDP(Client):
    server_type = "UDP"
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.data, client = self.listen_sock.sock.recvfrom(1024)
        self.listen_sock.sock.sendto(self.data, client)
        self.client_addr, self.client_port = client
        self.write_log()

    def handle_data(self, try_send):
        raise RuntimeError("Attempted handle_data on UDP")

class ClientTCP(Client):
    server_type = "TCP"
    def __init__(self, *args, **kwargs):
        """
        Accept a connection on listensock, and become a new client
        """
        super().__init__(*args, **kwargs)

        self.sock, client = self.listen_sock.sock.accept()
        self.client_addr, self.client_port = client
        self.data = b""
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


    def close_early(self):
        """
        Handle when the client closed earlier than age-related death
        """
        self.closed_early = True
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
        except BrokenPipeError as e:
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
            except BrokenPipeError as e:
                self.close_early()
                return
        
        return






def main_loop(port_list):
    """
    The main loop for execution - ends with an exception (including Ctrl+C)
    :param list port_list: A list of integers of ports to listen on
    """
    listen_socks = ListenList(port_list)
    drop_privileges()
    client_list = ClientList(listen_socks)
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
    parser.add_argument("--logstash-server",
            help="The server address for logstash", default = None)
    parser.add_argument("--logstash-port", type=int,
            help="The TCP port for logstash server", default = 5959)
    args = parser.parse_args()

    logger.addHandler(logging.StreamHandler())
    if args.logstash_server is not None:
        logger.addHandler(
                logstash.TCPLogstashHandler(
                    args.logstash_server,
                    args.logstash_port,
                    version = 1)
                )

    handler = logging.handlers.SysLogHandler(address="/dev/log")
    handler.setFormatter(logging.Formatter("ECHO_AND_LOG: %(message)s"))
    logger.addHandler(handler)

    logger.setLevel(logging.INFO)

    main_loop(args.port_list)
