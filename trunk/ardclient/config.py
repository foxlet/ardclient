# Ardclient
#
# Author: Dan Keder <dan.keder@gmail.com>

from optparse import OptionParser
import ConfigParser
import pwd
import re
import sys

import utils

__all__ = [ "Config" ]


class Config:
    ''' ARD configuration.
    
        This class provides interface to the configuration file and command line options.
    '''

    def __init__(self):

        options, args = self.parse_args()

        config = ConfigParser.ConfigParser()
        try:
            config.readfp(open(options.config_file, 'r'))
        except IOError, e:
            sys.stderr.write("%s\n" % e)
            sys.exit(1)

        #----------------------------------------------------------------------
        # Listen
        #----------------------------------------------------------------------
        (address, port) = config.get("ardclient", "listen").rsplit(":", 1)
        if not address or not port:
            raise ValueError("Invalid listen address.")
        self.listen_addr = utils.IPv4Address(address)
        self.listen_port = int(port)


        #----------------------------------------------------------------------
        # MAC address
        #----------------------------------------------------------------------
        if config.has_option("ardclient", "mac_address"):
            self.mac_addr = utils.MacAddress(config.get("ardclient", "mac_address"))
        else:
            self.mac_addr = utils.getMacAddress()

        #----------------------------------------------------------------------
        # Verbosity
        #----------------------------------------------------------------------
        self.verbose = options.verbose

        #----------------------------------------------------------------------
        # Ping frequency
        #----------------------------------------------------------------------
        self.ping_freq = int(config.get("ardclient", "ping_frequency"))

        #----------------------------------------------------------------------
        # User
        #----------------------------------------------------------------------
        self.user = config.get("ardclient", "user")

        #----------------------------------------------------------------------
        # Group
        #----------------------------------------------------------------------
        self.group = config.get("ardclient", "group")

        #----------------------------------------------------------------------
        # Admin login
        #----------------------------------------------------------------------
        self.admin_login = config.get("ardclient", "admin_login")

        #----------------------------------------------------------------------
        # Admin passwd
        #----------------------------------------------------------------------
        self.admin_passwd = config.get("ardclient", "admin_passwd")

        #----------------------------------------------------------------------
        # reboot_cmd
        #----------------------------------------------------------------------
        self.reboot_cmd = config.get("ardclient", "reboot_cmd")

        #----------------------------------------------------------------------
        # poweroff_cmd
        #----------------------------------------------------------------------
        self.poweroff_cmd = config.get("ardclient", "poweroff_cmd")

        #----------------------------------------------------------------------
        # sudo_cmd
        #----------------------------------------------------------------------
        self.sudo_cmd = config.get("ardclient", "sudo_cmd")

        #----------------------------------------------------------------------
        # admin_list
        #----------------------------------------------------------------------
        self.admin_list = config.get("ardclient", "admin_list")

        #----------------------------------------------------------------------
        # message_cmd
        #----------------------------------------------------------------------
        self.message_cmd = config.get("ardclient", "message_cmd")


    def parse_args(self):
        parser = OptionParser()
        parser.add_option("-c", "--config-file", dest="config_file", 
                help="path to the configuration file", metavar="FILE")
        parser.add_option("-v", "--verbose", dest="verbose", action="store_true",
                help="verbose operation")

        parser.set_defaults(config_file="/etc/ard/ardclient.conf")
        parser.set_defaults(verbose=False)

        (options, args) = parser.parse_args()

        return options, args

    def get_listen(self):
        return (self.listen_addr.get_text(), self.listen_port)

    def get_listen_addr(self):
        return self.listen_addr

    def get_listen_port(self):
        return self.listen_port

    def get_verbose(self):
        return self.verbose;

    def get_mac_addr(self):
        return self.mac_addr

    def get_ping_frequency(self):
        return self.ping_freq

    def get_admin_list_file(self):
        return self.admin_list_file

    def get_user(self):
        return self.user

    def get_user_id(self):
        return pwd.getpwnam(self.user)[2]

    def get_group(self):
        return self.user

    def get_group_id(self):
        return pwd.getpwnam(self.group)

    def get_admin_login(self):
        return self.admin_login

    def get_admin_passwd(self):
        return self.admin_passwd

    def get_reboot_cmd(self):
        return self.reboot_cmd

    def get_poweroff_cmd(self):
        return self.poweroff_cmd

    def get_sudo_cmd(self):
        return self.sudo_cmd

    def get_admin_list(self):
        return self.admin_list

    def get_message_cmd(self):
        return self.message_cmd
