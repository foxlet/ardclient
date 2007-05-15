# Ardclient
#
# Author: Dan Keder <dan.keder@gmail.com>

from ardclient import packet
from ardclient import utils

#----------------------------------------------------------------------
#
# Ping
#
#----------------------------------------------------------------------

# Outgoing packet codes
CODE_PING        = 0x0077
CODE_PING_REPLY  = 0x0076

def make_ping_packet(mac_addr):
    ''' Make ping packet.
        
        @type mac_addr:  utils.MacAddress
        @param mac_addr:  Client MAC address
    '''
    format = "!H 2s H 6s 6s"
    fields = (
            3,  # counter 1
            "\x00\x30",
            7,  # counter 2
            "\x04" * 6,
            mac_addr.get_bytes()
    )
    return packet.create(CODE_PING, format, fields)

def parse_ping_response(response_data):
    ''' Parse ping response.

        @return: Returns tuple (added_in_admin, admin_mac_addr)
    '''
    packet2 = packet.create_from(response_data, "!H I H 6s")

    added_in_admin = (packet2.get_field(2) == 0x02)
    admin_mac_addr = utils.MacAddress(packet2.get_field(3))
    return (added_in_admin, admin_mac_addr)

#    print "Counter 1:", fields[0]
#    print "Counter 2:", fields[1]
#    print "Added in admin:", fields[2]
#    print "Admin MAC address:", debug.format_mac_address(packet2.field(3))


def send_ping(sock, config, target):
    ''' Send ARD ping to the target.
    '''

    # 1. packet
    ping_packet = ping.make_ping_packet(self.config.get_mac_addr())

    self.network.write(ping_packet, target)

    # 2. packet
    response_data = self.network.read_from(target)
    response = ping.parse_ping_response(response_data)
