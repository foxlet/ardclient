# Ardclient
#
# Author: Dan Keder <dan.keder@gmail.com>

import struct

from ardclient import packet
from ardclient import utils

#----------------------------------------------------------------------
#
# Send Command
#
#----------------------------------------------------------------------

# Incoming packet codes
CODE_SEND_CMD     = 0x006b
CODE_CANCEL_CMD   = 0x006d

# Outgoing packet codes
CODE_ACK_PACKET   = 0x0000
CODE_CMD_RESULTS  = 0x005f
CODE_CMD_RESULTS_2 = 0x006c

def parse_packet_1(packet_data):
    ''' Parse 1. packet of send_command.

        @type  packet_data: Packet
        @param packet_data: Data of 1. packet.
        @return: (task_id, user, cmd)
    '''
    cmd_len = struct.unpack("!B", packet_data.get_data()[45])[0]
    format = "!I 41s %dp xx" % (cmd_len+1)
    packet1 = packet.create_from(packet_data, format)

    task_id = packet1.get_field(0)
    user = utils.null_terminated(packet1.get_field(1))
    cmd = packet1.get_field(2)

    return (task_id, user, cmd)


def make_packet_2():
    ''' Make 2. packet of send_command. '''
    format = "!HH"
    fields = (
            CODE_SEND_CMD,
            0x0000
    )
    return packet.create(CODE_ACK_PACKET, format, fields)

def make_packet_3(task_id):
    ''' Make 3. packet of send_command. Notification, that the task has
        been started.

        @type  task_id:  Number
        @param task_id:  Task ID of the started task.
    '''
    format = "!I 10s"
    fields = (
            task_id,
            "\x00\x3c\x00\x0d\x93\xb7\x7c\xe8\xbf\xff"
    )
    return packet.create(CODE_CMD_RESULTS, format, fields)

def parse_packet_4(packet_data):
    ''' Parse 4. packet of send_command. 

        @type  packet_data:  Packet
        @param packet_data:  Data of the packet.
    '''
    if packet_data.get_code() == CODE_ACK_PACKET:
        return packet.create_from(packet_data, "!HB")
    else:
        raise RuntimeError("Unexpected packet received. Expected: 0x%x  Received: 0x%x" 
                % (CODE_ACK_PACKET, packet_data.get_code()))

def make_packet_5(task_id, mac_addr, output):
    ''' Make 5. packet of send_command. Task is finished and we want to
        send results back to the admin.

        @type task_id:  Number
        @param task_id:  Task ID.
        @type mac_addr:  utils.MacAddress
        @param mac_addr:  Client MAC address.
        @type output:  str
        @param output:  text output of the task.
    '''
    format = "!I 2s 6s %ds" % len(output)
    fields = (
            task_id,
            "\x00\x40",
            mac_addr.get_bytes(),
            output
    )
    return packet.create(CODE_CMD_RESULTS, format, fields)

def parse_packet_6(packet_data):
    ''' Parse 6. packet of send_command. 

        @type  packet_data:  Packet
        @param packet_data:  Data of the packet.
    '''
    if packet_data.get_code() == CODE_ACK_PACKET:
        return packet.create_from(packet_data, "!HB")
    else:
        raise RuntimeError("Unexpected packet received. Expected: 0x%x  Received: 0x%x" 
                % (CODE_ACK_PACKET, packet_data.get_code()))

def make_packet_7(output, status):
    ''' Make 7. packet of send_command. Send back results and exit code.
    
        @type output:  str
        @param output:  Output of the task.
        @type status:  Number
        @param status:  Exit code of the task.
    '''
    if output:
        output = output.splitlines()[-1]
    format = "!B 3s %ds" % (len(output)+1) # len of output + terminating NULL
    fields = (
            status,
            "\x00\x01\x00",
            output
    )
    return packet.create(CODE_CMD_RESULTS_2, format, fields)

def parse_packet_8(packet_data):
    ''' Parse 8. packet of send_command. 

        @type  packet_data:  Packet
        @param packet_data:  Data of the packet.
    '''
    if packet_data.get_code() == CODE_ACK_PACKET:
        return packet.create_from(packet_data, "!HB")
    else:
        raise RuntimeError("Unexpected packet received. Expected: 0x%x  Received: 0x%x" 
                % (CODE_ACK_PACKET, packet_data.get_code()))

def make_packet_9(task_id, mac_addr):
    ''' Make 9. packet of send_command. We want to send information,
        that the task is finished.

        @type task_id:  Number
        @param task_id:  Task ID.
        @type mac_addr:  utils.MacAddress
        @param mac_addr:  Client MAC address.
    '''
    format = "!I 2s 6s"
    fields = (
            task_id,
            "\x00\x41",
            mac_addr.get_bytes()
    )
    return packet.create(CODE_CMD_RESULTS, format, fields)

def parse_packet_10(packet_data):
    ''' Parse 10. packet of send_command. 

        @type  packet_data:  Packet
        @param packet_data:  Data of the packet.
    '''
    if packet_data.get_code() == CODE_ACK_PACKET:
        return packet.create_from(packet_data, "!HB")
    else:
        raise RuntimeError("Unexpected packet received. Expected: 0x%x  Received: 0x%x" 
                % (CODE_ACK_PACKET, packet_data.get_code()))

def parse_cancel_packet_1(packet_data):
    ''' Parse cancelling packet. '''
    if packet_data.get_code() == CODE_CANCEL_CMD:
        return packet.create_from(packet_data, "")
    else:
        raise RuntimeError("Unexpected packet received. Expected: 0x%x  Received: 0x%x" 
                % (CODE_CANCEL_CMD, packet_data.get_code()))

def make_cancel_packet_2():
    ''' Make answer for cancelling packet. '''
    format = "!HB"
    fields = (
            CODE_CANCEL_CMD,
            0x00
    )
    return packet.create(CODE_ACK_PACKET, format, fields)





class TaskError(Exception):
    pass
