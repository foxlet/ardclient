# Ardclient
#
# Author: Dan Keder <dan.keder@gmail.com>

from ardclient import packet

#----------------------------------------------------------------------
#
# Remove Computer
#
#----------------------------------------------------------------------

# Incoming packet codes
CODE_REMOVE_COMPUTER   = 0x7d02

def parse_packet_1(packet1_data):
    ''' Parse 1. packet of remove_computer.

        @type packet1_data:  Packet
        @param packet1_data:  Data of 1. packet.
    '''
    return packet.create_from(packet1_data, "")
