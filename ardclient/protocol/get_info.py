# Ardclient
#
# Author: Dan Keder <dan.keder@gmail.com>

import struct

from ardclient import packet
from ardclient import debug

#----------------------------------------------------------------------
#
# Get Info
#
#----------------------------------------------------------------------

### Packet codes
CODE_GET_INFO = 0x0014
CODE_ANSWER_GET_INFO = 0x0001

### Status codes
STATUS_AVAIL_NO_FOCUS   = 0x0001 # Available, no focused application
STATUS_AVAIL            = 0x0002 # Available
STATUS_WAITING          = 0x0003 # Waiting
STATUS_NONE             = 0x0004 # (None)
STATUS_NONE_NO_FOCUS    = 0x0007 # (None), no focused application
STATUS_RECVING_SCREEN   = 0x0008 # Receiving screen: %@
STATUS_ERROR            = 0x0009 # Error: %@
STATUS_LOCKED           = 0x000d # Locked screen
STATUS_GENERATING_REPORT = 0x000f # Generating Report
STATUS_DELETING         = 0x0010 # Deleting Items
STATUS_COPYING          = 0x0011 # Copying Items
STATUS_CHATTING         = 0x0012 # Chatting: 
STATUS_SLEEPING         = 0x0016 # Sleeping:
STATUS_SLEEPING_NO_FOCUS = 0x0017 # Sleeping, no current application
STATUS_SCREENSAVER      = 0x0018 # Screen Saver, no current application
STATUS_INSTALLING       = 0x0019 # Installing package
STATUS_LOGIN_WINDOW     = 0x001a # Login Window
STATUS_SENDING_SCREEN   = 0x001b # Sending Screen
STATUS_RUNNING_CMD      = 0x001c # Running UNIX Command
STATUS_EMPTYING_TRASH   = 0x001d # Emptying Trash


def parse_packet_1(data):
    ''' Parse 1. packet of get_info.

        @type data: Packet
        @param data:  Received data.
    '''
    return packet.create_from(data, "!B")

def make_packet_2(status_code, focused_window, logged_user, hostname, 
        client_ip_address, client_mac_address, last_activity):
    ''' Make 2. packet of get_info.
    
        @type status_code: int
        @param status_code:  The state the client machine is in
        (available, busy...).
        @type focused_window: str
        @param focused_window:  The title of the
        currently focused window on. the client machine or empty string
        if no window is focused.
        @type logged_user: str
        @param logged_user:  Username of the currently logged user.
        @type hostname: str
        @param hostname:  Client hostname.
        @type client_ip_address: utils.IPv4Address
        @param client_ip_address  Client ip address.
        @type client_mac_address: utils.MacAddress
        @param client_mac_address:  Client MAC address.
        @type last_activity: int
        @param last_activity:  Number of seconds since last activity on
        the client computer.
    '''
    size = struct.pack("!H", len(hostname))
    hostname_utf16 = size + hostname.encode('utf-16-be')  # hostname in UTF-16, big-endian
    hostname_utf16 += "\x00" * (128-len(hostname_utf16))

    format = "!20s IIII H H 48p H 32p 32p 32s I 8s 4s 4s I 6s 6s I 128s H"      # POZOR zmena!!! 128s -> 128p
    fields = (
        "\x00\x30\x00\x10\x28\x02\x84\x32\x90\x7d\xab\x0c\xbf\xff\xfb\xa0\xbf\xff\xf5\x10",
        0x00304a10,
        0x003047b0,
        0x00304a18,
        0x00000001,
        status_code,
        0x0000,
        focused_window[:47],
        0x0030,
        logged_user,
        hostname,
        "\x00\x10\x90\x7d\xc8\x50\x00\x00\x00\x04\x00\x31\x91\xd0\x90\x7d\xc5\x10\x90\x7f\x04\x34\xbf\xff\xf5\xb0\x00\x31\x57\x30\x90\x7f", #"\x00\x00" + "\x01" * 30,
        0x800000ff,   # security flags
        "\x01\x00\x00\x00\x00\x00\x02\x00", #"\x03" * 8,
        client_ip_address.get_bytes(),
        "\x00\x00\x00\x00",
        last_activity * 64,  # one second is 64
        "\x00\x00\x00\x00\x00\x00",
        client_mac_address.get_bytes(),
        0x1048,
        hostname_utf16,
        #"\x00\x07\x00n\x00e\x00m\x00e\x00s\x00i\x00s" + "\x00" * 112,
        0x1100
    )
    return packet.create(CODE_ANSWER_GET_INFO, format, fields)


