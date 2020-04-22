from Encryption_Object import *
from EmailCode import *
from validate_email import validate_email


class ClientHandler(threading.Thread):
    def __init__(self, socket, address, data_base, client_handlers, email_object):
        """Supers threading class, creates encryption object and arguments to the script."""
        super(ClientHandler, self).__init__()
        self.socket = socket
        self.ip = address[0]
        self.port = address[1]
        self.data_base = data_base
        self.client_handlers = client_handlers
        self.email_object = email_object
        self.name = None
        self.connected = True
        self.aes = AESEncryption(False)
        self.rsa = RSAEncryption()
        self.replaced_keys = False
    
    def replace_keys(self):
        self.send_message(self.rsa.get_publickey().decode())
        aes_key = self.rcv_message()
        aes_key = self.rsa.decrypt(aes_key)
        self.aes.set_key(aes_key)
        print(self.rsa.get_publickey())
        print(self.aes.get_key())
        self.replaced_keys = True
        return
        

    def check_login(self, message):
        """Gets a message and check if the user can register or login or get his password in the mail."""
        if message == '':  # The client has been disconnected
            return False, 'break'
        if message.startswith('login:') and len(message.split(',')) == 2:  # Checks if this is a login
            name = message[message.index('login:') + len('login:'):message.index(',')]
            password = message[message.index(',') + 1:]
            if not self.data_base.check_key_in_database(name):
                self.send_message('No such username')
                return False, ''
            elif self.data_base.read_from_data_base('name', name, 'password') == password:
                self.client_handlers.update({name: self})
                self.name = name
                self.send_message('Connected')
                return True, 'login'
            else:
                self.send_message('Wrong password')
                return False, ''
        elif message.startswith('register:') and len(message.split(',')) == 3:  # Checks if this is a register
            name = message[message.index('register:') + len('register:'):message.index(',')]
            message = message[message.index(name + ',') + len(name + ','):]
            password = message[:message.index(',')]
            email = message[message.index(',') + 1:]
            if not self.data_base.check_key_in_database(name):
                if True:  # checks if the email is valid and if it's exist
                    self.send_message('Connected')
                    self.send_message('users:' + ','.join(self.data_base.get_all_user_names()) + '^')
                    self.data_base.add_to_data_base(name, password, email)
                    self.client_handlers.update({name: self})
                    self.name = name
                    self.email_object.send_register_email(email, name)
                    return True, 'register'
                else:
                    self.send_message('Wrong email')
                    return False, ''
            else:
                self.send_message('There is such username')
                return False, ''
        elif message.startswith('forgot password:'):
            username = message[message.index('forgot password:') + len('forgot password:'):]
            if self.data_base.check_key_in_database(username):
                message_broadcast = 'Your Password: ' + self.data_base.read_from_data_base('name', username, 'password')
                self.email_object.send_email_with_message(self.data_base.read_from_data_base('name', username, 'email'),
                                                          'Your Password', message_broadcast)
                self.send_message('sent password')
                return False, ''
            else:
                self.send_message('No such username')
                return False, ''
        else:
            self.send_message('Wrong data')
            return False, ''

    def run(self):
        """Get a message from the client and act as needed."""
        self.replace_keys()
        print('raplaced')
        self.connected = False
        how_connected = None
        while not self.connected:
            m = self.rcv_message()
            self.connected, how_connected = self.check_login(m)
            if how_connected == 'break':
                break
        if self.connected:
            if how_connected == 'register':
                # Sends to all the users that there is a new user and they need to add him
                self.send_broadcast_message(self.data_base.get_all_user_names(), 'users:' + self.name + '^')
            # Gets the list of messages when the user was disconnected
            str_list_messages = self.data_base.read_from_data_base('name', self.name, 'list_messages')
            if len(str_list_messages) > 0:
                for message in str_list_messages.split(','):
                    self.send_message(message + '^')
                    self.data_base.set_to_data_base(self.name, '', 'list_messages')
            while self.connected:
                message = self.rcv_message()
                if message == '':
                    self.connected = False
                elif message.startswith('#private#'):
                    # Checks if the message is private and sends the message to the right user if he's connected
                    # and if he's is'nt saves the message in database
                    message = message.replace('#private#', '')
                    username_to_send = message[0: message.index('@')]
                    message = '#private#' + self.name + ':' + message[message.index('@') + 1:] + '^'
                    self.send_private_message(username_to_send, message)
                else:  # The message is a group message and we send the message to all users
                    self.send_broadcast_message(self.data_base.get_all_user_names(), self.name + ':' + message)
        if self.name != '':
            del self.client_handlers[self.name]
        return None

    def send_broadcast_message(self, list_names, message):
        """Sends a message to all the connected users and save the message to the disconnected users."""
        for name in list_names:
            if name != self.name:
                if name in self.client_handlers:
                    self.client_handlers[name].send_message(message)
                else:
                    str_list_messages = self.data_base.read_from_data_base('name', name, 'list_messages')
                    str_list_messages += message + ','
                    self.data_base.set_to_data_base(name, str_list_messages, 'list_messages')

    def send_private_message(self, name, message):
        """Sends a private message to user if he's connected and if he is'nt the function saves the message for him."""
        if self.name != name:
            if name in self.client_handlers:
                self.client_handlers[name].send_message(message)
            else:
                str_list_messages = self.data_base.read_from_data_base('name', name, 'list_messages')
                str_list_messages += message + ','
                self.data_base.set_to_data_base(name, str_list_messages, 'list_messages')

    def send_message(self, message):
        """Sends a message to the client with encryption."""
        if self.replaced_keys:
            self.socket.send(self.aes.encrypt(message).encode())
        else:
            self.socket.send(message.encode())

    def rcv_message(self):
        """Get a message from the client and encrypt the message back to normal."""
        if self.replaced_keys:
            return self.aes.decrypt(self.socket.recv(1024).decode())
        else:
            return self.socket.recv(1024).decode()
