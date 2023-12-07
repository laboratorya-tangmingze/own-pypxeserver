# coding: utf-8

from dhcppython.exceptions import MalformedPacketError
from dhcppython.options import options, OptionList
from dhcppython.packet import DHCPPacket
from tftpy import TftpServer

from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler
from ipaddress import ip_interface
from logging import basicConfig, FileHandler, getLogger, StreamHandler, \
    DEBUG, INFO, \
    debug, info, warning
from os.path import getsize, join
from socket import gethostname, socket, \
    AF_INET, SOCK_DGRAM, SO_BROADCAST, SO_REUSEADDR, SOL_SOCKET
from sys import exit
from threading import Thread
from time import sleep

class udp_server:
    def __init__(self, debug=False, log_file='server.log'):
        self.unicast = '0.0.0.0'
        self.siaddr = '192.168.0.17'
        self.mask = '255.255.255.0'
        self.router = '192.168.0.251'
        self.dns = '223.5.5.5'
        self.broadcast = '255.255.255.255'
        self.lease_time = 120
        self.begin = '192.168.0.100'
        self.end = '192.168.0.110'
        self.path = r'C:\Users\Administrator\Downloads\own-pypxe\files'
        self.kernel = 'ipxe-x86_64.efi'
        self.menu = 'boot.ipxe'
        # logging
        if debug:
            logging_level = DEBUG
        else:
            logging_level = INFO
        basicConfig(
            level=logging_level,
            format='%(asctime)s.%(msecs)03d %(name)s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                FileHandler(log_file, mode='a', encoding=None),
                StreamHandler()
            ]
        )
        self.logger = getLogger('udp_server')
        # threading
        self.threadings = {}
    def start(self):
        self.logger.info(f'PATH {self.path}')
        try:
            # dhcpc
            self.threadings.update(self.dhcpc(logger=self.get_short_logger('DHCPc')))
            # dhcpd
            self.threadings.update(self.dhcpd(logger=self.get_short_logger('DHCPd')))
            # proxy_dhcpd
            self.threadings.update(self.proxy_dhcpd(logger=self.get_short_logger('PorxyDHCPd')))
            # tftpd
            self.threadings.update(self.tftpd(logger=self.get_short_logger('TFTPd'), path=self.path))
            # httpd
            self.threadings.update(self.httpd(logger=self.get_short_logger('HTTPd'), path=self.path))
            # thread to start
            [dicts['_thread'].start() for dicts in self.threadings.values() if dicts is not None]
            while all(map(lambda dicts: dicts['_thread'].is_alive(), self.threadings.values())):
                sleep(1)
        except KeyboardInterrupt:
            [dicts['_stop']() for dicts in self.threadings.values() if dicts is not None]
            exit()
    def udp_socket(self):
        socks = socket(AF_INET, SOCK_DGRAM)
        socks.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        socks.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        return socks
    def get_logger(self, root_name, child_name):
        '''
        e.g. self.get_logger(self.logger.name, 'DHCPc')
        '''
        return getLogger(f'{root_name}.{child_name}')
    def get_short_logger(self, child_name):
        '''
        e.g. self.get_short_logger('DHCPc')
        '''
        return getLogger(f'{child_name}')
    def dhcpc(self, logger):
        logger.info(f'(68) {self.unicast} started...')
        def _stop():
            logger.info(f'(68) stopped...')
        def _thread():
            another_dhcpd = []
            socks.bind((self.unicast, 68))
            while socks is not None:
                try:
                    msg, addr = socks.recvfrom(65536)
                    dhcp_packet = DHCPPacket.from_bytes(msg)
                except MalformedPacketError as e:
                    logger.warning(f'(68) {e}')
                    continue
                dhcp_server = ip_interface(dhcp_packet.options.by_code(54).data).ip
                if dhcp_server not in another_dhcpd:
                    logger.info(f'(68) discovering for another DHCPd on LAN') if not another_dhcpd else ''
                    logger.info(f'(68) another DHCPd detected on your LAN @ {dhcp_server}')
                    another_dhcpd.append(dhcp_server)
                    logger.info('(68) {} received, MAC {}, XID {}'.format(
                        dhcp_packet.msg_type, \
                        dhcp_packet.chaddr, \
                        dhcp_packet.xid
                    ))
                    logger.debug('(68) msg is %s' % msg)
        socks = server.udp_socket()
        return {'dhcpc' : {'_thread' : Thread(target=_thread, daemon=True), '_stop' : _stop}}
    def dhcpd(self, logger):
        logger.info(f'(67) {self.unicast} started...')
        def _stop():
            logger.info(f'(67) stopped...')
        def _thread():
            socks.bind((self.unicast, 67))
            while socks is not None:
                try:
                    msg, addr = socks.recvfrom(65536)
                    dhcp_packet = DHCPPacket.from_bytes(msg)
                except MalformedPacketError as e:
                    logger.warning(f'(67) {e}')
                    continue
                vendor_class = dhcp_packet.options.by_code(60)
                if dhcp_packet.msg_type == 'DHCPDISCOVER' and vendor_class:
                    logger.info('(67) {} received, MAC {}, XID {}'.format(
                        dhcp_packet.msg_type, \
                        dhcp_packet.chaddr, \
                        dhcp_packet.xid
                    ))
                    logger.debug('(67) msg is %s' % msg)
                    user_class = dhcp_packet.options.by_code(77)
                    file_name = self.menu
                    if user_class:
                        logger.info(f'(67) iPXE user-class detected')
                        file_name = self.menu
                    else:
                        file_name = self.kernel
                    offer_packet = DHCPPacket.Offer(
                        seconds=0, \
                        tx_id=dhcp_packet.xid, \
                        mac_addr=dhcp_packet.chaddr, \
                        yiaddr=self.unicast, \
                        use_broadcast=True, \
                        relay=self.unicast, \
                        sname=gethostname().encode('unicode-escape'), \
                        fname=file_name.encode('unicode-escape'), \
                        option_list=OptionList([
                            options.short_value_to_object(13, round(getsize(join(self.path, file_name))/1024)*2), \
                            options.short_value_to_object(54, ip_interface(self.siaddr).ip.packed), \
                            options.short_value_to_object(60, 'PXEClient'), \
                            options.short_value_to_object(66, self.siaddr)
                        ])
                    )
                    offer_packet.siaddr = ip_interface(self.siaddr).ip
                    logger.info('(67) {} sent, {}:68, XID {}'.format(
                        offer_packet.msg_type, \
                        self.broadcast, \
                        offer_packet.xid
                    ))
                    offer_packet = offer_packet.asbytes
                    logger.debug(f'(67) offer_packet is {offer_packet}')
                    socks.sendto(offer_packet, (str(self.broadcast), 68))
                else:
                    logger.info('(67) {} discarded, MAC {}, XID {}'.format(
                        dhcp_packet.msg_type, \
                        dhcp_packet.chaddr, \
                        dhcp_packet.xid
                    ))
        socks = server.udp_socket()
        return {'dhcpd' : {'_thread' : Thread(target=_thread, daemon=True), '_stop' : _stop}}
    def proxy_dhcpd(self, logger):
        logger.info(f'(4011) {self.siaddr} started...')
        def _stop():
            logger.info(f'(4011) stopped...')
        def _thread():
            socks.bind((self.siaddr, 4011))
            while socks is not None:
                try:
                    msg, addr = socks.recvfrom(65536)
                    dhcp_packet = DHCPPacket.from_bytes(msg)
                except MalformedPacketError as e:
                    logger.warning(f'(4011) {e}')
                    continue
                uuid_guid_based_client = dhcp_packet.options.by_code(97)
                if uuid_guid_based_client:
                    logger.info('(4011) {} received, MAC {}, XID {}'.format(
                        dhcp_packet.msg_type, \
                        dhcp_packet.chaddr, \
                        dhcp_packet.xid
                    ))
                    logger.debug('(4011) msg is %s' % msg)
                    file_name = self.kernel
                    ack_packet = DHCPPacket.Ack(
                        seconds=0, \
                        tx_id=dhcp_packet.xid, \
                        mac_addr=dhcp_packet.chaddr, \
                        yiaddr=self.unicast, \
                        use_broadcast=False, \
                        relay=self.unicast, \
                        sname=gethostname().encode('unicode-escape'), \
                        fname=file_name.encode('unicode-escape'), \
                        option_list=OptionList([
                            options.short_value_to_object(13, round(getsize(join(self.path, file_name))/1024)*2), \
                            options.short_value_to_object(54, ip_interface(self.siaddr).ip.packed), \
                            options.short_value_to_object(60, 'PXEClient'), \
                            options.short_value_to_object(66, self.siaddr), \
                            options.bytes_to_object(uuid_guid_based_client.asbytes)
                        ])
                    )
                    ack_packet.siaddr = ip_interface(self.siaddr).ip
                    logger.info('(4011) {} sent, {}:4011, XID {}'.format(
                        ack_packet.msg_type, \
                        ack_packet.ciaddr, \
                        ack_packet.xid
                    ))
                    ack_packet = ack_packet.asbytes
                    logger.debug(f'(4011) ack_packet is {ack_packet}')
                    socks.sendto(ack_packet, (str(dhcp_packet.ciaddr), 4011))
        socks = server.udp_socket()
        return {'proxy_dhcpd' : {'_thread' : Thread(target=_thread, daemon=True), '_stop' : _stop}}
    def tftpd(self, logger, path):
        '''
        info(f'TFTPd (69) {tftp-server} started...')
        info(f'TFTPd (69) DoReadFile boot.ipxe B 1432 T 74')
        info(f'TFTPd (69) DoReadFile boot.ipxe.cfg B 1432 T 351')
        info(f'TFTPd (69) DoReadFile menu.ipxe B 1432 T 1709')
        info(f'TFTPd (69) stopped...')
        '''
        logger = getLogger('tftpy')
        logger.setLevel(INFO)
        logger.info(f'(69) {self.unicast} started...')
        def _stop():
            logger.info(f'(69) stopped...')
        def _thread():
            server.listen(self.unicast, 69)
        server = TftpServer(tftproot=path)
        return {'tftpd' : {'_thread' : Thread(target=_thread, daemon=True), '_stop' : _stop}}
    def httpd(self, logger, path):
        '''
        info(f'HTTPd (80) {http-server} started...')
        info(f'')
        info(f'HTTPd (80) stopped...')
        '''
        logger.info(f'(80) {self.unicast} started...')
        def _stop():
            logger.info(f'(80) stopped...')
        def _thread():
            server.serve_forever()
        server = HTTPServer((self.unicast, 80), partial(SimpleHTTPRequestHandler, directory=path))
        return {'httpd' : {'_thread' : Thread(target=_thread, daemon=True), '_stop' : _stop}}

if __name__ == '__main__':
    server = udp_server(debug=True)
    server.start()