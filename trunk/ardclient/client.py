# Ardclient
#
# Author: Dan Keder <dan.keder@gmail.com>

from Crypto.Hash import SHA256
from subprocess import Popen, PIPE, STDOUT
import cPickle as pickle
import crypt
import grp
import os
import pwd
import socket 


from protocol import get_info, add_computer, remove_computer, send_command, ping, shutdown, send_message
import debug
import packet
import utils



class Ardclient:

    def __init__(self, config):
        self.config = config
        self.network = NetworkIO(config.get_listen())
        self.admin_list = AdminList(self.config.get_admin_list())
        self.tasklist = TaskList()


    def start(self):
        ''' Start ARD client.
        '''
        verbose = self.config.get_verbose()
        counter = 0

        while (True):

            received = self.network.read(timeout=1)
            counter += 1


            if received == None:
                ### No data was received.

                ### Send partial output from running tasks
                for issuer in self.tasklist.get_issuers():
                    task = self.tasklist.get_task(issuer)
                    self.handle_send_output(issuer, task)

                ### Check running tasks
                for issuer in self.tasklist.get_issuers():
                    task = self.tasklist.get_task(issuer)
                    if task.is_finished():
                        self.handle_finished_task(issuer, task)

                ### Ping registered admins
                if counter >= self.config.get_ping_frequency():
                    self.ping_admins()
                    counter = 0


            else:
                ### Data received, handle it.
                (data, sender) = received

            
                if data.get_code() == ping.CODE_PING_REPLY:
                    # Ping reply
                    debug.log(debug.MSG_INFO, "Received ping reply from %s" % sender, verbose)
                    self.handle_ping_reply(data, sender)
                    continue

                if data.get_code() == add_computer.CODE_ADD_COMPUTER:
                    ### Add computer
                    debug.log(debug.MSG_INFO, "Received event \"Add Computer\"", verbose)
                    self.handle_add_computer(data, sender)
                    continue


                elif data.get_code() == remove_computer.CODE_REMOVE_COMPUTER:
                    ### Remove computer
                    debug.log(debug.MSG_INFO, "Received event \"Remove Computer\"", verbose)
                    self.handle_remove_computer(data, sender)
                    continue


                ### Check authorization.
                if not self.admin_list.check_admin(sender) :
                    continue

                if data.get_code() == get_info.CODE_GET_INFO:
                    ### Get info
                    debug.log(debug.MSG_INFO, "Received event \"Get Info\"", verbose)
                    self.handle_get_info(data, sender)
                    continue


                elif data.get_code() == send_command.CODE_SEND_CMD:
                    ### Send command
                    debug.log(debug.MSG_INFO, "Received event \"Send Command\"", verbose)
                    self.handle_send_command(data, sender)
                    continue

                elif data.get_code() == send_command.CODE_CANCEL_CMD:
                    ### Cancel command
                    debug.log(debug.MSG_INFO, "Received event \"Cancel Command\"", verbose)
                    self.handle_cancel_command(data, sender)
                    continue


                elif data.get_code() == shutdown.CODE_SHUTDOWN:
                    ### Shutdown/Restart computer
                    debug.log(debug.MSG_INFO, "Received event \"Shutdown/Restart Computer\"", verbose)
                    self.handle_shutdown_restart(data, sender)
                    continue

                elif data.get_code() == send_message.CODE_SEND_MESSAGE:
                    ### Send message
                    debug.log(debug.MSG_INFO, "Received event \"Send message\"", verbose)
                    self.handle_send_message(data, sender)
                    continue


                debug.log(debug.MSG_ERROR, "Received unknown event: 0x%x" % data.get_code(), verbose)



    def handle_add_computer(self, packet1_data, sender):
        ''' Handle Add Computer request. 

            Communicate with the SENDER and authenticate him. If
            successfull, add SENDER to the list of admin computers.

            @type packet1_data: Packet
            @param packet1_data: First packet of the communication.
            @type sender: utils.IPv4Address
            @param sender: Sender IP address.
        '''
        # 1. packet
        packet1 = add_computer.parse_packet_1(packet1_data)

        # 2. packet
        g = 0x17  # generator
        (public_key, private_key) = utils.generate_key_pair(g)
        packet2 = add_computer.make_packet_2(g, public_key)
        self.network.write(packet2, sender)

        # 3. packet
        packet3_data = self.network.read_from(sender)
        (admin, auth_data) = add_computer.parse_packet_3(packet3_data, private_key)

        # Decrypt username/password
        plaintext = utils.decrypt(admin.get_shared_key(), auth_data)
        username = utils.null_terminated(plaintext[0:32])
        password = utils.null_terminated(plaintext[64:96])

        # 4. packet
        if self.check_user(username, password):
            allow_access = True
            self.admin_list.add_admin(sender, admin)
        else:
            allow_access = False

        packet4 = add_computer.make_packet_4(allow_access, 
                self.config.get_listen_addr(),
                self.config.get_mac_addr())
        self.network.write(packet4, sender)

    def check_user(self, user, password):
        ''' Check, if the provided user and password is valid.
        
            @return: Returns True if valid, False otherwise.
        '''
        (salt, passwd) = self.config.get_admin_passwd().split('$', 1)
        salted_password = salt + password
        hashed_password = SHA256.new(salted_password).hexdigest()
        if passwd == hashed_password and user == self.config.get_admin_login():
            return True
        else:
            return False




    def handle_get_info(self, data, sender):
        ''' Handle get_info event.
            
            @type data: Packet
            @param data:  First packet of the communication.
            @type sender: utils.IPv4Address
            @param sender:  Sender IP address.
        '''
        packet1 = get_info.parse_packet_1(data)
        
        window_title = utils.get_focused_window()[:46] + '\x00'
        current_user = utils.get_current_user()[:30] + '\x00'
        hostname = utils.get_hostname()[:30] + '\x00'
        packet2 = get_info.make_packet_2(
                get_info.STATUS_AVAIL,
                window_title,
                current_user,
                hostname,
                self.config.get_listen_addr(),
                self.config.get_mac_addr(),
                1800)
        self.network.write(packet2, sender)


    def handle_remove_computer(self, data, sender):
        ''' Handle remove_computer event.
            
            @type data: Packet
            @param data: First packet of the communication.
            @type sender: utils.IPv4Address
            @param sender:  Sender IP address.
        '''
        packet1 = remove_computer.parse_packet_1(data)
        # Remote Desktop send remove_computer on its exit, but does not
        # send add_computer on its start.
        #self.admin_list.remove_admin(sender)


    def handle_send_command(self, data, sender):
        ''' Handle send_command event.
            
            @type data: Packet
            @param data:  First packet of the communication.
            @type sender: utils.IPv4Address
            @param sender:  Sender IP address.
        '''
        # 1. packet
        (task_id, user, cmd) = send_command.parse_packet_1(data)

        if not user:
            user = utils.get_current_user()

        sudo_cmd = self.config.get_sudo_cmd()
        cmd = "%s -u '%s' %s" % (sudo_cmd, user, cmd)

        ### Create task
        task = Task(task_id, user, cmd)

        # 2. packet
        packet2 = send_command.make_packet_2()
        self.network.write(packet2, sender)

        ### Run task and add task to the running task list
        task.run()
        self.tasklist.add_task(sender, task)

        # 3. packet
        packet3 = send_command.make_packet_3(task.get_task_id())
        self.network.write(packet3, sender)

        # 4. packet
        packet4_data = self.network.read_from(sender)
        packet4 = send_command.parse_packet_4(packet4_data)


    def handle_cancel_command(self, data, sender):
        ''' Handle send_unix_command event.
            
            @type data: Packet
            @param data:  First packet of the communication.
            @type sender: utils.IPv4Address
            @param sender:  Sender IP address.
        '''
        cancel = send_command.parse_cancel_packet_1(data)
        task = self.tasklist.get_task(sender)
        if task == None:
            debug.log(debug.MSG_WARN, "Cancelling non-existing task", self.config.get_verbose())
        else:
            ### Kill task and remove it from the task list
            task.kill()
            self.tasklist.remove_task(sender)

        cancel2 = send_command.make_cancel_packet_2()
        self.network.write(cancel2, sender)


    def handle_send_output(self, issuer, task):
        ''' Send partial output of the running task.
            
            @param issuer: Task issuer
            @param task: Running task
        '''
        output = task.read_output()

        ### Send the output back to admin per-partes.
        while output:
            chunk = output[0:1387]
            output = output[1387:]
            chunk += '\x00'    # NULL-terminate the chunk

            # 5. packet
            packet5 = send_command.make_packet_5(task.get_task_id(), 
                    self.config.get_mac_addr(), chunk)
            self.network.write(packet5, issuer)

            # 6. packet
            packet6_data = self.network.read_from(issuer)
            packet6 = send_command.parse_packet_6(packet6_data)


    def handle_finished_task(self, issuer, task):
        ''' Send results of the finished task back to the admin.

            @param issuer: task issuer
            @param task: Finished task
        '''
        if not task.is_finished():
            raise ArdclientError("The task has not finished yet!")

        ### Task finished, send results back to admin.
        output = task.read_output()
        status = task.wait()

        # 7. packet
        packet7 = send_command.make_packet_7(output, status)
        self.network.write(packet7, issuer)

        # 8. packet
        packet8_data = self.network.read_from(issuer)
        packet8 = send_command.parse_packet_8(packet8_data)

        # 9. packet
        packet9 = send_command.make_packet_9(task.get_task_id(), 
                self.config.get_mac_addr())
        self.network.write(packet9, issuer)

        # 10. packet
        packet10_data = self.network.read_from(issuer)
        packet10 = send_command.parse_packet_10(packet10_data)

        ### Remove task from the list of running tasks
        self.tasklist.remove_task(issuer)


    def handle_shutdown_restart(self, packet_data, sender):
        ''' Handle shutdown_restart request.
        '''
        # 1. packet
        action = shutdown.parse_packet_1(packet_data)

        # 2. packet
        packet2 = shutdown.make_packet_2()
        self.network.write(packet2, sender)
        
        ### Poweroff/reboot computer.
        if action == shutdown.ACTION_REBOOT \
        or action == shutdown.ACTION_REBOOT_KILL:
            self.reboot_computer()
        elif action == shutdown.ACTION_SHUTDOWN \
        or action == shutdown.ACTION_SHUTDOWN_KILL:
            self.shutdown_computer()



    def shutdown_computer(self):
        ''' Power off the computer.
        '''
        os.system(self.config.get_poweroff_cmd())

    def reboot_computer(self):
        ''' Reboot the computer.
        '''
        os.system(self.config.get_reboot_cmd())

    def handle_send_message(self, packet_data, sender):
        ''' Handle send_message event. '''
        # 1. packet
        (hostname, author, message) = send_message.parse_packet_1(packet_data)

        # 2. packet
        packet2 = send_message.make_packet_2()
        self.network.write(packet2, sender)

        # Run message_cmd
        message_cmd = self.config.get_message_cmd()
        message_cmd = message_cmd.replace('%h', hostname).replace('%n', author).replace('%s', message).replace('%%', '%')

        os.system(message_cmd + '&')



    def ping_admins(self):
        ''' Send ping to every registered admin computer.'''
        verbose = self.config.get_verbose()
        for admin in self.admin_list.get_keys():
            debug.log(debug.MSG_INFO, "Ping %s:%s" % admin, verbose)
            self.send_ping(admin)

    def send_ping(self, target):
        ''' Send ARD ping to the target.

            @type target:  (str, int)
            @param target:  Address where we want to send the ping.
        '''
        # 1. packet
        ping_packet = ping.make_ping_packet(self.config.get_mac_addr())
        self.network.write(ping_packet, target)

    def handle_ping_reply(self, data, sender):
        ''' Handle ping reply.'''
        pass
        #response = ping.parse_ping_response(response_data)



class AdminList:
    def __init__(self, filename):
        self.filename = filename
        try:
            self.load_list()
        except IOError:
            self.admin_list = {}


    def add_admin(self, key, admin):
        ''' Register admin computer.

            @type key: str
            @param key: Unique key identifying admin.
            @type admin: add_computer.Admin
            @param admin: Admin computer to register.
        '''
        self.admin_list[key] = admin
        self.save_list()

    def remove_admin(self, key):
        ''' Unregister admin computer. The client will not
            be administered with this computer any further.
            
            @type  key:  str
            @param key:  Key identifying the admin computer.
        '''
        if self.admin_list.has_key(key):
            del self.admin_list[key]
            self.save_list()

    def get_admin(self, key):
        ''' Get admin associated with the KEY.
        '''
        if self.admin_list.has_key(key):
            return self.admin_list[key]
        else:
            raise ValueError("There is no such admin: " % str(key))

    def check_admin(self, key):
        ''' Check whether the admin is in admin list.'''
        return self.admin_list.has_key(key)

    def get_keys(self):
        ''' Return list of keys. Each key can be used in get_admin()
            method to retrieve specific admin computer. 
        '''
        return self.admin_list.keys()

    def load_list(self):
        self.admin_list = pickle.load(open(self.filename))

    def save_list(self):
        pickle.dump(self.admin_list, open(self.filename, 'w'))



class NetworkIO:
    ''' NetworkIO class provides interface for reading data from network
        and writing data to network.
    '''
    def __init__(self, listen):
        ''' Creates socket and binds it to the specified address.
            
            @type listen: (str, int)
            @param listen:  Tuple containing the IP address and port that
            we want to listen on.
        '''
        self.listen = listen
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(self.listen)


    def write(self, data, dest_addr):
        ''' Send data to DEST.

            @type data: Packet
            @param data:  Packet that we want to send.
            @type dest_addr: (int, str)
            @param dest_addr:  Destination address.
        '''
        self.s.sendto(data.get_bytes(), dest_addr)

    def read(self, size=65535, timeout=None):
        ''' Receive data from the network socket.

            If TIMEOUT is specified, socket will be set to non-blocking
            mode. If no data is received until timeout, the function
            returns None. Otherwise, if TIMEOUT is None, the socket will
            be in blocking mode and will wait for any incoming data.
            Specifying TIMEOUT to 0 will make the function return
            immediately, if there is no incoming data.
            
            @type size: int
            @param size:  Size of the buffer used to receive data.
            @type timeout: int
            @param timeout:  Socket timeout.
            @return:  Tuple containing received data and sender address,
            or None if no data is received until timeout.
        '''
        try:
            self.s.settimeout(timeout)
            (data, sender) = self.s.recvfrom(size)
            p = packet.parse(data)
            return (p, sender)
        except socket.timeout:
            return None

    def read_from(self, src_addr, size=65535, timeout=None):
        ''' Receive at most SIZE bytes of data, that were
            sent from host with address and port SRC_ADDR and SRC_PORT.

            Any incoming data that are not from the specified address
            will be discarded!

            If TIMEOUT is specified, socket will be set to non-blocking
            mode. If no data is received until timeout, the function
            returns None. Otherwise, if TIMEOUT is None, the socket will
            be in blocking mode and will wait for any incoming data.
            Specifying TIMEOUT to 0 will make the function return
            immediately, if there is no incoming data.
            
            @type size: int
            @param size: Size of the buffer used to receive data.
            @type timeout: int
            @param timeout:  Socket timeout.

            @type src_addr: (str, int)
            @param src_addr:  Tuple containing source address and port,
            that we want to receive data from. 

            @return:  Received data, or None if no data is received until
            timeout.
        '''
        try:
            self.s.settimeout(timeout)
            sender = None
            while sender != src_addr:
                (data, sender) = self.s.recvfrom(size)
            return packet.parse(data)

        except socket.timeout:
            return None


class Task:
    ''' Task that runs the specified UNIX command in a separate process.
        It provides methods to read the output the command and to get
        its return return.
    '''
    def __init__(self, task_id, username, cmd):
        ''' @param task_id: Task id.
            @param username: User to run the task as.
            @param cmd: Command to run.
        '''
        self.task_id = task_id
        self.cmd = cmd
        self.username = username
        self.p = None

    def get_task_id(self):
        return self.task_id

    def get_cmd(self):
        return self.cmd

    def get_username(self):
        return self.username

    def get_uid(self):
        return pwd.getpwnam(self.username)[2]

    def get_pid(self):
        ''' Get process id of the running task. '''
        if self.is_running():
            return self.p.pid
        else:
            raise TaskError("The task was not started")

    def run(self):
        ''' Run task in a separate process.'''
        if not self.is_running():
            self.p = Popen(
                args=self.cmd,
                shell=True,
                stdout=PIPE,
                stderr=STDOUT,
                universal_newlines=True)
    #            preexec_fn=lambda: os.setuid(task.get_uid()))
        else:
            raise TaskError("The task is already running")

    def read_output(self):
        ''' Read output of the task.
        
            @return:  Output of the task.
        '''
        if self.p != None:
            return self.p.stdout.read()
        else:
            raise TaskError("The task was not started")

    def wait(self):
        ''' Wait for task to finish.
        
            @return:  Returns return-code of the task.
        ''' 
        if self.p != None:
            status = self.p.wait()
            return status
        else:
            raise TaskError("The task was not started")

    def is_running(self):
        ''' Check if the task is running.

            @return:  True if the task is running, False otherwise.
        '''
        return self.p != None

    def is_finished(self):
        ''' Check if the task finished.

            @return:  Returns True if the task is finished, False
            otherwise.
        '''
        if self.is_running():
            return self.p.poll() != None
        else:
            return False

    def kill(self, signal=9):
        ''' Send signal to the running task.

            @type signal:  Number
            @param signal:  Signal to send.
        '''
        if self.is_running():
            os.kill(self.get_pid(), signal)
        else:
            raise TaskError("The task has not been started yet!")


class TaskList:
    def __init__(self):
        self.tasklist = {}

    def add_task(self, issuer, task):
        ''' Add a task to the list of running tasks.
            @type task: Task
            @param task: Task we want to add.
            @param issuer: Address of the task issuer.
        '''
        if self.tasklist.has_key(issuer):
            raise ArdclientError("Issuer can have only one running task!")

        if task == None or not task.is_running():
            raise ArdclientError("Can not add stopped task to the list of running tasks.")

        self.tasklist[issuer] = task

    def remove_task(self, issuer):
        ''' Remove the task from the list of running tasks.
            @param issuer: Issuer whose task we want to remove.
        '''
        if not self.tasklist.has_key(issuer):
            raise ArdclientError("Can not remove task from the non-existent issuer.")
        del self.tasklist[issuer]

    def get_task(self, issuer):
        ''' Get task associated with given issuer.

            @param issuer: Issuer of the task.
            @return: Returns the task associated with the issuer or None
            if there is no such task.
        '''
        if self.tasklist.has_key(issuer):
            return self.tasklist[issuer]
        else:
            return None

    def get_issuers(self):
        ''' Return the list of issuers. '''
        return self.tasklist.keys()


class ArdclientError(Exception):
    pass
