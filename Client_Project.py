from tkinter import *
import socket
from Encryption_Object import *
import threading
import os.path
import glob
from time import gmtime, strftime


class Client(object):

    def __init__(self, ip, port):
        """Creates Encryption Object to encrypt the messages.
        Creates a socket to communicate with the server."""
        self.server_ip = ip
        self.server_port = port
        self.my_socket = socket.socket()
        self.my_socket.connect((self.server_ip, self.server_port))
        self.aes = AESEncryption()
        self.rsa = RSAEncryption(False)
        self.replaced_keys = False
        self.replace_keys()
      
    def replace_keys(self):
      rsa_publickey = self.rcv_message().encode()
      self.rsa.set_publickey(rsa_publickey)
      encrypted_aes_key = self.rsa.encrypt(self.aes.get_key())
      self.send_message(encrypted_aes_key)
      print(self.rsa.get_publickey())
      print(self.aes.get_key())
      self.replaced_keys = True

    def send_message(self, message):
        """Sends a message to the server with encryption."""
        if self.replaced_keys:
          self.my_socket.send(self.aes.encrypt(message).encode())
        else:
          self.my_socket.send(message.encode())

    def rcv_message(self):
        """Get a message from the server and encrypt the message back to normal."""
        if self.replaced_keys:
          return self.aes.decrypt(self.my_socket.recv(1024).decode())
        else:
          return self.my_socket.recv(1024).decode()

    def stop(self):
        """Close the connection with the server."""
        self.my_socket.close()


class AccountGUI(object):
    def __init__(self, client_obj):
        """Define the arguments to the GUI but doesn't create them yet."""
        self.client = client_obj
        self.main_screen = None
        self.username = None
        self.password = None
        self.username_entry = None
        self.password_entry = None
        self.username_info = ''
        self.password_info = ''
        self.register_screen = None
        self.login_screen = None
        self.username_verify = None
        self.password_verify = None
        self.username_login_entry = None
        self.password_login_entry = None
        self.user_exists_screen = None
        self.password_not_rec_screen = None
        self.user_not_found_screen = None
        self.email_entry = None
        self.email = None
        self.forgot_screen = None
        self.send_password_screen = None
        self.wrong_email_screen = None
        self.empty_input_screen = None
        self.login_or_register_verify = False
        self.account_screen()

    def register(self):
        """Designing window for registration"""
        self.register_screen = Toplevel(self.main_screen)
        self.register_screen.title('Register')
        self.register_screen.geometry('300x300')

        self.username = StringVar()
        self.password = StringVar()
        self.email = StringVar()

        Label(self.register_screen, text="Please enter details below", bg="light blue").pack()
        Label(self.register_screen, text="").pack()
        username_label = Label(self.register_screen, text="Username * ")
        username_label.pack()
        self.username_entry = Entry(self.register_screen, textvariable=self.username)
        self.username_entry.pack()
        password_label = Label(self.register_screen, text="Password * ")
        password_label.pack()
        self.password_entry = Entry(self.register_screen, textvariable=self.password, show='*')
        self.password_entry.pack()
        email_label = Label(self.register_screen, text="Email * ")
        email_label.pack()
        self.email_entry = Entry(self.register_screen, textvariable=self.email)
        self.email_entry.pack()
        Label(self.register_screen, text="").pack()
        Button(self.register_screen, text="Register", width=10, height=1, bg="blue", command=self.register_user).pack()

    def login(self):
        """Designing window for login"""
        self.login_screen = Toplevel(self.main_screen)
        self.login_screen.title("Login")
        self.login_screen.geometry("300x300")
        Label(self.login_screen, text="Please enter details below to login", bg="light blue").pack()
        Label(self.login_screen, text="").pack()

        self.username_verify = StringVar()
        self.password_verify = StringVar()

        Label(self.login_screen, text="Username * ").pack()
        self.username_login_entry = Entry(self.login_screen, textvariable=self.username_verify)
        self.username_login_entry.pack()
        Label(self.login_screen, text="").pack()
        Label(self.login_screen, text="Password * ").pack()
        self.password_login_entry = Entry(self.login_screen, textvariable=self.password_verify, show='*')
        self.password_login_entry.pack()
        Label(self.login_screen, text="").pack()
        Button(self.login_screen, text="Login", width=10, height=1, command=self.login_verify).pack()
        Label(self.login_screen, text="").pack()
        Button(self.login_screen, text="Forgot Password", width=15, height=1, command=self.forgot).pack()

    def forgot(self):
        """Designing window for forgot password"""
        self.login_screen.destroy()
        self.forgot_screen = Toplevel(self.main_screen)
        self.forgot_screen.title("Forgot Password")
        self.forgot_screen.geometry("300x200")
        Label(self.forgot_screen, text="Please enter details below \nto get the password in your email",
              bg="light blue").pack()
        Label(self.forgot_screen, text="").pack()

        self.username_verify = StringVar()

        Label(self.forgot_screen, text="Username * ").pack()
        Entry(self.forgot_screen, textvariable=self.username_verify).pack()
        Label(self.forgot_screen, text="").pack()
        Button(self.forgot_screen, text="Send Password", width=10, height=1, command=self.forgot_verify).pack()

    def register_user(self):
        """Implementing event on register button"""
        username1 = self.username.get()
        password1 = self.password.get()
        email1 = self.email.get()
        if username1 != '' and password1 != '' and email1 != '':
            self.client.send_message('register:' + username1 + ',' + password1 + ',' + email1)
            answer = self.client.rcv_message()
            if answer == 'Connected':
                self.username_info = username1
                self.password_info = password1
                self.login_or_register_verify = True
                self.main_screen.destroy()
            elif answer == 'Wrong email':
                self.wrong_email()
            elif answer == 'There is such username':
                self.user_already_exist()
        else:
            self.empty_input(self.register_screen)

    def login_verify(self):
        """Implementing event on login button"""
        username1 = self.username_verify.get()
        password1 = self.password_verify.get()
        if username1 != '' and password1 != '':
            self.client.send_message('login:' + username1 + ',' + password1)
            answer = self.client.rcv_message()
            self.username_login_entry.delete(0, END)
            self.password_login_entry.delete(0, END)
            if answer == 'Connected':
                self.username_info = username1
                self.password_info = password1
                self.login_or_register_verify = True
                self.main_screen.destroy()
            elif answer == 'Wrong password':
                self.password_not_recognised()
            elif answer == 'No such username':
                self.user_not_found(self.login_screen)
        else:
            self.empty_input(self.login_screen)

    def forgot_verify(self):
        """Implementing event on forgot password button"""
        username1 = self.username_verify.get()
        self.client.send_message('forgot password:' + username1)
        answer = self.client.rcv_message()
        if answer == 'No such username':
            self.user_not_found(self.forgot_screen)
        else:
            self.send_password()

    def empty_input(self, screen):
        """Designing popup for login username is exists"""
        self.empty_input_screen = Toplevel(screen)
        self.empty_input_screen.title("Failed")
        self.empty_input_screen.geometry("150x100")
        Label(self.empty_input_screen, text="No input").pack()
        Button(self.empty_input_screen, text="OK", command=self.delete_empty_input_screen).pack()

    def user_already_exist(self):
        """Designing popup for login username is exists"""
        self.user_exists_screen = Toplevel(self.login_screen)
        self.user_exists_screen.title("Failed")
        self.user_exists_screen.geometry("150x100")
        Label(self.user_exists_screen, text="User Is Already Exists ").pack()
        Button(self.user_exists_screen, text="OK", command=self.delete_user_exists_screen).pack()

    def password_not_recognised(self):
        """Designing popup for login invalid password"""
        self.password_not_rec_screen = Toplevel(self.login_screen)
        self.password_not_rec_screen.title("Failed")
        self.password_not_rec_screen.geometry("150x100")
        Label(self.password_not_rec_screen, text="Invalid Password ").pack()
        Button(self.password_not_rec_screen, text="OK", command=self.delete_password_not_recognised).pack()

    def user_not_found(self, screen):
        """Designing popup for user not found"""
        self.user_not_found_screen = Toplevel(screen)
        self.user_not_found_screen.title("Failed")
        self.user_not_found_screen.geometry("150x100")
        Label(self.user_not_found_screen, text="User Not Found").pack()
        Button(self.user_not_found_screen, text="OK", command=self.delete_user_not_found_screen).pack()

    def send_password(self):
        """Designing popup for sent password"""
        self.send_password_screen = Toplevel(self.forgot_screen)
        self.send_password_screen.title("Success")
        self.send_password_screen.geometry("150x100")
        Label(self.send_password_screen, text="Sent Password \nTo Your Email").pack()
        Button(self.send_password_screen, text="OK", command=self.delete_send_password_screen).pack()

    def wrong_email(self):
        """Designing popup for wrong email"""
        self.wrong_email_screen = Toplevel(self.forgot_screen)
        self.wrong_email_screen.title("Failed")
        self.wrong_email_screen.geometry("150x100")
        Label(self.wrong_email_screen, text="Wrong email or \nemail doesn't exist.").pack()
        Button(self.wrong_email_screen, text="OK", command=self.delete_wrong_email_screen).pack()

    def delete_user_exists_screen(self):
        """Deleting popups"""
        self.user_exists_screen.destroy()

    def delete_send_password_screen(self):
        """Deleting popups"""
        self.send_password_screen.destroy()
        self.forgot_screen.destroy()

    def delete_password_not_recognised(self):
        """Deleting popups"""
        self.password_not_rec_screen.destroy()

    def delete_user_not_found_screen(self):
        """Deleting popups"""
        self.user_not_found_screen.destroy()

    def delete_wrong_email_screen(self):
        """Deleting popups"""
        self.wrong_email_screen.destroy()

    def delete_empty_input_screen(self):
        """Deleting popups"""
        self.empty_input_screen.destroy()

    def account_screen(self):
        """Designing Main(first) window"""
        self.main_screen = Tk()
        self.main_screen.geometry("300x200")
        self.main_screen.title("Account Login")
        Label(text="Select Your Choice", bg="light blue", width="300", height="2", font=('Ariel', 13)).pack()
        Label(text="").pack()
        Button(text="Login", height="2", width="30", command=self.login).pack()
        Label(text="").pack()
        Button(text="Register", height="2", width="30", command=self.register).pack()
        Label(text="").pack()
        self.main_screen.mainloop()
        if not self.login_or_register_verify:
            quit()


class BotBubble:
    def __init__(self, master, root, message, time, who, list_messages):
        y_pos = 160
        if len(list_messages) > 0:
            y_pos = list_messages[-1].master.bbox(list_messages[-1].i)[-1] + 65
        m = ''
        len_line = 20
        if ' ' in message:
            current_line = ''
            words = message.split(' ')
            for word in words:
                if len(word) <= len_line:
                    if len(current_line) + len(word) + 1 <= len_line:
                        current_line += word + ' '
                        m += word + ' '
                    else:
                        m += '\n' + word + ' '
                        current_line = word + ' '
                else:
                    for index in range(0, len(word), len_line):
                        if len(word) - index >= 0:
                            new_word = word[index: index + len_line]
                        else:
                            new_word = word[index: len(word) - index]
                        if len(current_line) + len(new_word) + 1 <= len_line:
                            current_line += new_word + ' '
                            m += new_word + ' '
                        else:
                            m += '\n' + new_word + ' '
                            current_line = new_word + ' '
        else:
            for index in range(0, len(message), len_line):
                if len(message) - index >= len_line:
                    m += message[index: index + len_line] + '\n'
                else:
                    m += message[index: len(message) - index]
        message = m
        if who == 'me':
            self.master = master
            self.frame = Frame(master, bg="light grey")
            self.i = self.master.create_window(310, y_pos, window=self.frame)
            Label(self.frame, text=time, font=("Helvetica", 12),
                  bg="light grey", foreground="grey").grid(
                row=0, column=0, sticky="w", padx=5)
            Label(self.frame, text=message, font=("Helvetica", 14), bg="light grey").grid(
                row=1, column=0,
                sticky="w",
                padx=5, pady=3)
            root.update_idletasks()
            self.master.create_polygon(self.draw_triangle(self.i), fill="light grey", outline="light grey")
        else:
            self.master = master
            self.frame = Frame(master, bg="white")
            self.i = self.master.create_window(90, y_pos, window=self.frame)
            Label(self.frame, text=time, font=("Helvetica", 12),
                  bg="white", foreground="grey").grid(
                row=0, column=0, sticky="w", padx=5)
            Label(self.frame, text=message, font=("Helvetica", 14), bg="white").grid(row=1, column=0, sticky="w",
                                                                                     padx=5, pady=3)
            root.update_idletasks()
            self.master.create_polygon(self.draw_triangle(self.i), fill="white", outline="white")

    def draw_triangle(self, widget):
        x1, y1, x2, y2 = self.master.bbox(widget)
        return x1, y2 - 10, x1 - 15, y2 + 10, x1, y2


class ChatGUI(object):
    def __init__(self, client_obj, name):
        """Define the arguments to the GUI but doesn't create them yet."""
        self.client = client_obj
        self.name = name
        self.main_screen = None
        self.listbox = None
        self.txt = None
        self.input_user = None
        self.input_field = None
        self.input_user = None
        self.GUI_runs = True
        self.current_chat = 'Group'
        self.GUI_build = False
        self.canvas = None
        self.messages_objects = []
        if not os.path.isdir(self.name):
            os.mkdir(self.name)
            os.mkdir(self.name + '/chats')
            open(self.name + '/chats/Group.txt', 'w')
        self.run_gui()

    def run_gui(self):
        """Creates a thread to wait for a message from the server,
        And creates the GUI and run the GUI and the thread."""
        thread = threading.Thread(target=self.rcv_messages)
        thread.start()
        self.main_chat_screen()
        quit()
        self.GUI_runs = False
        self.client.stop()

    def enter_list_pressed(self, event):
        """After the user pressed Enter the function adds the message to the chat's file and sends the message to the
        server .If the user is in the chat uploads the message to the screen."""
        print(event)
        input_get = self.input_field.get()
        time = strftime("%Y-%m-%d %H:%M", gmtime())
        if input_get != '':
            if self.current_chat == 'Group':
                self.client.send_message(input_get + '(' + time + ')')
            else:
                self.client.send_message(
                    '#private#' + self.current_chat + '@' + input_get + '(' + time + ')')
            with open(self.name + '/chats/' + self.current_chat + '.txt', 'a') as file_to_write:
                file_to_write.write(input_get + '(' + time + ')' + '\n')
            self.canvas.move(ALL, 0, -65)
            self.messages_objects.append(
                BotBubble(self.canvas, self.main_screen, input_get, time, 'me', self.messages_objects))
            self.input_user.set('')
        return "break"

    def main_chat_screen(self):
        """Designing Main window"""
        self.main_screen = Tk()
        self.main_screen.title('Chat')
        self.listbox = Listbox(self.main_screen, width=10, height=20, bg='light gray')
        self.listbox.grid(row=0, column=1)
        frame = Frame(self.main_screen, width=300, height=300)
        frame.grid(row=0, column=0)
        self.canvas = Canvas(frame, width=400, height=350, bg="light blue")
        vbar = Scrollbar(frame, orient=VERTICAL)
        vbar.pack(side=RIGHT, fill=Y)
        vbar.config(command=self.canvas.yview)
        self.canvas.config(yscrollcommand=vbar.set)
        self.canvas.pack(side=LEFT, expand=True, fill=BOTH)
        self.input_user = StringVar()
        self.input_field = Entry(self.main_screen, text=self.input_user, width=30)
        self.input_field.grid(row=1, column=0)
        self.input_field.bind("<Return>", self.enter_list_pressed)
        self.listbox.bind("<Double-Button-1>", self.click_on_listbox)
        chats_list = [f for f in glob.glob(self.name + "/chats/*.txt")]
        for chat_name in chats_list:
            chat_name = chat_name[chat_name.index('chats/') + len('chats/'):chat_name.index('.txt')]
            if chat_name != '':
                self.listbox.insert(END, [chat_name])
        with open(self.name + '/chats/Group.txt', 'r') as file_to_read:
            self.canvas.delete("all")
            messages = file_to_read.read().split('\n')[:-1]
            for message in messages:
                self.canvas.move(ALL, 0, -65)
                time = message[message.index('(') + 1:message.index(')')]
                message = message[:message.index('(')]
                if ':' in message:
                    self.messages_objects.append(
                        BotBubble(self.canvas, self.main_screen, message, time, 'not me', self.messages_objects))
                else:
                    self.messages_objects.append(
                        BotBubble(self.canvas, self.main_screen, message, time, 'me', self.messages_objects))
        self.GUI_build = True
        self.main_screen.mainloop()

    def click_on_listbox(self, event):
        """After the user chose a chat the function takes the messages of this text and uploads them to the screen."""
        widget = event.widget
        selection = widget.curselection()
        value = widget.get(selection[0])[0]
        self.messages_objects = []
        with open(self.name + '/chats/' + value + '.txt', 'r') as file_to_read:
            messages = file_to_read.read().split('\n')[:-1]
            self.canvas.delete("all")
            for message in messages:
                self.canvas.move(ALL, 0, -65)
                time = message[message.index('(') + 1:message.index(')')]
                message = message[:message.index('(')]
                if ':' in message:
                    self.messages_objects.append(
                        BotBubble(self.canvas, self.main_screen, message, time, 'not me', self.messages_objects))
                else:
                    self.messages_objects.append(
                        BotBubble(self.canvas, self.main_screen, message, time, 'me', self.messages_objects))
        self.current_chat = value
        self.main_screen.title(value)
        self.listbox.itemconfig(self.listbox.get(0, END).index((value,)), {'fg': 'black'})

    def rcv_messages(self):
        """Get a message from the server and act as needed."""
        while not self.GUI_build:
            pass
        while self.GUI_runs:
            messages = client.rcv_message().split('^')
            if messages[0] == '':
                quit()
            for message in messages:
                if message != '':
                    if message.startswith('users:'):
                        list_names = message[len('users:'):].split(',')
                        for name in list_names:
                            if not os.path.isfile('chats/' + name + '.txt') and name != '':
                                open(self.name + '/chats/' + name + '.txt', 'w')
                            self.listbox.insert(END, [name])
                    elif message.startswith('#private#'):
                        message = message.replace('#private#', '')
                        username_send_from = message[:message.index(':')]
                        with open(self.name + '/chats/' + username_send_from + '.txt', 'a') as file_to_write:
                            file_to_write.write(message + '\n')
                        if self.current_chat == username_send_from:
                            self.canvas.move(ALL, 0, -65)
                            time = message[message.index('(') + 1:message.index(')')]
                            message = message[:message.index('(')]
                            self.messages_objects.append(
                                BotBubble(self.canvas, self.main_screen, message, time, 'not me',
                                          self.messages_objects))
                        else:
                            self.listbox.itemconfig(self.listbox.get(0, END).index((username_send_from,)),
                                                    {'fg': 'blue'})
                    else:
                        with open(self.name + '/chats/Group.txt', 'a') as file_to_write:
                            file_to_write.write(message + '\n')
                        if self.current_chat == 'Group':
                            self.canvas.move(ALL, 0, -65)
                            time = message[message.index('(') + 1:message.index(')')]
                            message = message[:message.index('(')]
                            self.messages_objects.append(
                                BotBubble(self.canvas, self.main_screen, message, time, 'not me',
                                          self.messages_objects))
                        else:
                            self.listbox.itemconfig(self.listbox.get(0, END).index(('Group',)),
                                                    {'fg': 'blue'})


if __name__ == "__main__":
    client = Client('127.0.0.1', 8080)
    account = AccountGUI(client)
    ChatGUI(client, account.username_info)
