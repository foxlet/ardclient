# Ardclient
#
# Author: Dan Keder <dan.keder@gmail.com>

from ardclient import packet
from ardclient import utils

#----------------------------------------------------------------------
#
# Send message
#
#----------------------------------------------------------------------

# Incoming packet codes
CODE_SEND_MESSAGE      = 0x0065

# Outgoing packet codes
CODE_ACK_PACKET        = 0x0000


def parse_packet_1(packet1_data):
    ''' Parse 1. packet of send_message.

        @type  packet1_data:  Packet
        @param packet1_data:  Data of the 1. packet.
    '''
    length = packet1_data.get_length() - 6
    packet1 = packet.create_from(packet1_data, "!HHH %ds" % length)

    hostname_length = packet1.get_field(0)
    author_length = packet1.get_field(1)
    msg_length = packet1.get_field(2)
    data = packet1.get_field(3).decode('utf-16-be')

    hostname = data[:hostname_length]
    author = data[hostname_length:hostname_length+author_length]
    message = data[hostname_length+author_length:]

    return (hostname, author, message)
    


def make_packet_2():
    ''' Make 2. packet of send_message. '''
    format = "!H H"
    fields = (
        CODE_SEND_MESSAGE,
        0
    )
    return packet.create(CODE_ACK_PACKET, format, fields)
