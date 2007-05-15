# Ardclient
#
# Author: Dan Keder <dan.keder@gmail.com>

import struct

import debug
    

def create(code, format, fields):
    ''' Create formatted packet with specified code, format and fields.

        @type code: int
        @param code:  Code of the packet.
        @type format: str
        @param format:  Format of the packet data (see struct.pack())
        @type fields: tuple
        @param fields:  Packet data fields
        @return:  Returns instance of class FormattedPacket.
    '''
    return FormattedPacket(code, format, fields)

def create_from(packet, format):
    ''' Create formatted packet from an existing instance of class
        Packet. You have to provide the format of the packet.

        @type packet: Packet
        @param packet:  Instance of class Packet or its subclass.
        @type format: str
        @param format:  Format of the packet data (see struct.pack())
        @return:  Returns instance of class FormattedPacket.
    '''
    fields = struct.unpack(format, packet.get_data())
    return FormattedPacket(packet.get_code(), format, fields)

def parse(raw_data):
    ''' Parse raw data and construct the packet. Only the packet header
        is parsed, because the format of the packet is unknown at the
        moment of receival.

        @type raw_data: str
        @param raw_data:  Raw packet data.
        @return:  Returns instance of class Packet.
    '''
    (code, data_size) = struct.unpack("!HH", raw_data[:4])
    data = raw_data[4:4+data_size]
    return Packet(code, data)



class Packet:
    ''' Generic ARD protocol packet.
    '''

    def __init__(self, code, data):
        ''' @type code: int
            @param code: Code of the packet.
            @type data: Packet
            @param data: Data part of the packet.
        '''
        self.code = code
        self.data = data

    def get_code(self):
        ''' Get packet code.
            @return:  Current packet code.
        '''
        return self.code

    def get_length(self):
        ''' Return length of the packet data (not packet itself)'''
        return len(self.get_data())

    def get_data(self):
        ''' Get data part of the packet.
            @return:  Data part of the packet.
        '''
        return self.data

    def get_bytes(self):
        ''' Convert packet into its binary form, for sending
            across network.

            @return:  Binary form of the packet.
        '''
        code = self.get_code()
        data = self.get_data()
        return struct.pack("!HH %ss" % len(data), code, len(data), data)




class FormattedPacket(Packet):
    ''' Packet with format.'''
    def __init__(self, code, format, fields):
        ''' @type code: int
            @param code:  Code of the packet.
            @type format: str
            @param format:  Format of the packet (see struct.pack).
            @type fields: tuple
            @param fields:  Data fields of the packet.
        '''
        self.code = code
        self.format = format
        self.fields = fields

    def get_data(self):
        ''' Get data part of the packet. In this class, it is computed
            from the format and fields.
        '''
        code = self.get_code()
        format = self.get_format()
        fields = self.get_field_list()
        return struct.pack(format, *fields)

    def get_format(self):
        return self.format


    def get_field_list(self):
        ''' Get data field list of the packet.
            @return: List of packet data fields.
        '''
        return self.fields

    def get_field(self, index):
        ''' Get data field with given INDEX.
            @return: Returns field with the given index.
        '''
        return self.fields[index]









#class Packet:
#    ''' Generic ARD protocol packet.
#    '''
#
#    def __init__(self, type, format, fields):
#        ''' @param packet_type  Type of the packet.
#            @param format  Format of the packet.
#            @param fields  Data fields of the packet.
#        '''
#        self._type = type
#        self._format = format
#        self._fields = fields
#
#
#    def type(self, new_type=None):
#        ''' Get/Set packet type.
#
#            @param new_type  New packet type.
#            @return Current packet type.
#        '''
#        if new_type != None:
#            self._type = new_type
#        return self._type
#
#
#    def format(self, new_format=None):
#        ''' Get/Set format of the packet.
#            
#            @param new_format New format of the packet.
#            @return Current packet format.
#        '''
#        if new_format != None:
#            self._format = new_format
#        return self._format
#    
#
#    def fields(self, new_fields=None):
#        ''' Get/Set data fields of the packet.
#            
#            @param new_fields  New data fields.
#            @return Current packet format.
#        '''
#        if new_fields != None:
#            self._fields = new_fields
#        return self._fields
#
#
#    def field(self, index):
#        ''' @return Return field with the given index.
#        '''
#        return self._fields[index]
#
#
#    def get_bytes(self):
#        ''' Convert packet into binary string, that can be sent across network.
#        '''
#        type = self._type
#        format = self._format
#        fields = self._fields
#        data = struct.pack(format, *fields)
#        data_len = len(data)
#        return struct.pack("!HH %ss" % (data_len), type, data_len, data)
#

#class PacketFactory:
#    ''' Packet factory is used to create and parse ARD packets.
#    '''
#    def __init__(self):
#        pass
#
#    def create(self, type, format, fields):
#        ''' Create new packet with specified type, format and fields.
#
#            @param type  type of the packet.
#            @param format  format of the packet data (see struct.pack())
#            @param fields  packet data fields
#            @return  Constructed packet.
#        '''
#        return Packet(type, format, fields)
#
#
#    def parse(self, data, format):
#        ''' Parse raw packet data according to the format.
#
#            @param data  raw packet data
#            @param format  format of data
#            @return  Parsed packet.
#        '''
#        (type, length) = self.parse_header(data)
#        payload = data[4:4+length]
#        fields = struct.unpack(format, payload)
#        return Packet(type, format, fields)
#
#    def parse_header(self, data):
#        ''' Parse only header of the packet.
#            
#            @param data  Raw packet data.
#            @return Packet type and length of data in a tuple.
#        '''
#        (type, length) = struct.unpack("!HH", data[:4])
#        return (type, length)
