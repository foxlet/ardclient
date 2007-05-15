# Ardclient
#
# Author: Dan Keder <dan.keder@gmail.com>

from Crypto.Util import number

from ardclient import packet
from ardclient import utils

#----------------------------------------------------------------------
#
# Add computer
#
#----------------------------------------------------------------------

# Incoming packet codes
CODE_ADD_COMPUTER      = 0x7d01
CODE_ADD_COMPUTER_2    = 0x7d00

# Outgoing packet codes
CODE_ACK_PACKET        = 0x0000




def parse_packet_1(packet1_data):
    ''' Parse 1. packet of add_computer.

        @type  packet1_data:  Packet
        @param packet1_data:  Data of the 1. packet.
    '''
    return packet.create_from(packet1_data, "!24s")

def make_packet_2(g, public_key):
    ''' Make 2. packet of add_computer.

        @type g: int
        @param g:  Generator number (see Diffie-Hellman protocol)
        @type public_key: int
        @param public_key:  Client public key.
    '''
    public_key_bytes = number.long_to_bytes(public_key)
    public_key_bytes += '\x00' * (64 - len(public_key_bytes))  # padding

    format = "!H 2s I 64s 18s"
    fields = (
        CODE_ADD_COMPUTER,
        "\x00\x00",
        g,
        public_key_bytes,
        "\x00" * 18
    )
    return packet.create(CODE_ACK_PACKET, format, fields)

def parse_packet_3(packet3_data, private_key):
    ''' Parse 3. packet of add_computer and gather useful data about the
        admin computer.

        @type packet3_data:  Packet
        @param packet3_data:  Data of the 3. packet.
        @type private_key:  Number
        @param private_key:  Client private key.
        @return:  Tuple containing Instance of class Admin and encrypted authentication data.
    '''
    packet3 = packet.create_from(packet3_data, "!64s xx 128s 128p 6s 16s 12s 42s 64x")
    if packet3.get_code() != CODE_ADD_COMPUTER_2:
        raise RuntimeError("Unexpected packet received. Expected: 0x%x  Received: 0x%x" 
                % (CODE_ADD_COMPUTER_2, packet3.get_code()))

    id = packet3.get_field(5)
    hostname = packet3.get_field(2)
    mac_addr = utils.MacAddress(packet3.get_field(3))
    serial_no = packet3.get_field(6)
    admin_public_key =  number.bytes_to_long(packet3.get_field(0))
    shared_key = utils.make_shared_key(admin_public_key, private_key)

    admin = Admin(id, hostname, mac_addr, serial_no, admin_public_key, shared_key)
    auth_data = packet3.get_field(1)

    return (admin, auth_data)

def make_packet_4(allow_access, ip_addr, mac_addr):
    ''' Make 4. packet of add_computer.

        @type  allow_access:  Boolean
        @param allow_access:  If true, admin provided correct username
        and password and we will grant him access. Otherwise, access
        will be denied.
        @type  ip_addr:  IPv4Address
        @param ip_addr:  Client IP address.
        @type  mac_addr:  MacAddress
        @param mac_addr:  Client MAC address.
        @return:  4. Packet of add_computer.
    '''
    if allow_access:
        format = "!H 10s 4s 6s 34s H"
        fields = (
            CODE_ADD_COMPUTER_2,
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x27",
            ip_addr.get_bytes(),
            mac_addr.get_bytes(),
            "\x00" * 34,
            0x4008
        )
        return packet.create(CODE_ACK_PACKET, format, fields)

    else:
        format = "!HH"
        fields = (
            CODE_ADD_COMPUTER_2,
            0xe6f7
        )
        return packet.create(CODE_ACK_PACKET, format, fields)



class Admin:
    def __init__(self, id, hostname, mac_addr, serial_no, public_key, shared_key):
        ''' This class provides information about the admin computer.
        
            @type  id:  str
            @param id:  ID of the admin computer.
            @type  hostname:  str
            @param hostname:  Hostname of the admin computer.
            @type  mac_addr:  utils.MacAddress
            @param mac_addr:  MAC address of the admin computer.
            @type  serial_no:  str
            @param serial_no:  Serial number of the Remote Desktop
            program on the admin computer.
            @type  public_key:  Number
            @param public_key:  Public key of the admin computer.
            @type  shared_key:  str
            @param shared_key:  Shared key of the admin computer.
        '''
        self.id = id
        self.hostname = hostname
        self.mac_addr = mac_addr
        self.serial_no = serial_no
        self.public_key = public_key
        self.shared_key = shared_key

    def get_id(self):
        return self.id

    def get_hostname(self):
        ''' @return: Returns hostname of the admin computer.
        '''
        return self.hostname

    def get_mac_addr(self):
        ''' @return: Returns MAC address of the admin computer.'''
        return self.mac_addr

    def get_serial_no(self):
        ''' @return: Returns serial number of the admin computer.'''
        return self.serial_no

    def get_public_key(self):
        ''' @return: Returns public key of the admin computer.'''
        return self.public_key

    def get_shared_key(self):
        ''' Get shared key.
            @return:  Shared key of the admin computer.
        '''
        return self.shared_key
