import socket
from Client_Handler_Project import *
from DataBase import *


class Server(object):
    def __init__(self):
        """Creates a socket an defines port and creates connection to the port in this computer"""
        self.sock = socket.socket()
        self.port = 8080
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.listen(1)

    def accept(self):
        """Accepts new client """
        return self.sock.accept()


def main():
    data_base = SyncDataBase()
    client_handlers = {}
    email_object = EmailObject('danielcyberchat@gmail.com', 'C' + 'y' + 'ber' + '$123456')
    server = Server()
    while True:
        client_socket, client_address = server.accept()
        ClientHandler(client_socket, client_address, data_base, client_handlers, email_object).start()


if __name__ == "__main__":
    main()
