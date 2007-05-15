# Ardclient
#
# Author: Dan Keder <dan.keder@gmail.com>

from ardclient import packet

#----------------------------------------------------------------------
#
# Shutdown/restart
#
#----------------------------------------------------------------------

# Incoming packet codes
CODE_SHUTDOWN          = 0x003d

# Outgoing packet codes
CODE_ACK_PACKET        = 0x0000


# Available actions
ACTION_REBOOT         = 0x00000001    # Restart computer, allow user to "save" his work.
ACTION_SHUTDOWN        = 0x00000002    # Shutdown computer, allow user to "save his work.
ACTION_REBOOT_KILL    = 0x00000003    # Restart computer, kill user processes.
ACTION_SHUTDOWN_KILL   = 0x00000004    # Shutdown computer, kill user processes.

def parse_packet_1(packet_data):
    ''' Parse 1. packet of shutdown_restart.
        
        @type packet_data: Packet
        @param packet_data: Packet data
        @return: Returns code of the action, that should be performed.
    '''
    packet1 = packet.create_from(packet_data, "!I")
    action = packet1.get_field(0)
    return action

def make_packet_2():
    ''' Make 2. packet of shutdown_restart. '''
    format = "!H H"
    fields = (
        CODE_SHUTDOWN,
        0
    )
    return packet.create(CODE_ACK_PACKET, format, fields)
