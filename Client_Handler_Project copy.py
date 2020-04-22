class ClientHandler(threading.Thread):
    def __init__(self, socket, address):
        """Supers threading class, creates encryption object and arguments to the script."""
        super(ClientHandler, self).__init__()
        self.socket = socket
        self.ip = address[0]
        self.port = address[1]

    def run(self):
        """Get a message from the client and act as needed."""
        message = "start"
        while message != "":
            message = self.rcv_message()
            self.send_message("OK")
       

    def send_message(self, message):
        """Sends a message to the client with encryption."""
        self.socket.send(message.encode())

    def rcv_message(self):
        """Get a message from the client and encrypt the message back to normal."""
        return self.socket.recv(1024).decode()
