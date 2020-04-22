import smtplib
import threading


class EmailObject(object):
    def __init__(self, sender, password):
        """Define the email details and create a Lock to manage the email object."""
        self.sender = sender
        self.__password = password
        self.lock = threading.Lock()

    def send_register_email(self, receiver, name):
        """Sends a registering message to new user."""
        self.lock.acquire()
        print('Got Email Lock')
        try:
            mail_server = smtplib.SMTP('s' + 'mtp.g' + 'mail.com', 587)
            mail_server.ehlo()
            mail_server.starttls()
            mail_server.login(self.sender, self.__password)
            msg = 'Subject:Welcome to the Chat world\nWelcome {0},\n We are delighted to have joined us ' \
                  'and hope you will enjoy our platform.'.format(name)
            mail_server.sendmail(self.sender, receiver, msg)
            mail_server.close()
        except smtplib.SMTPException:
            pass
        self.lock.release()
        print('Released Email Lock')

    def send_email_with_message(self, receiver, subject, message):
        """Sends a message to user."""
        self.lock.acquire()
        print('Got Email Lock')
        try:
            mail_server = smtplib.SMTP('s' + 'mtp.g' + 'mail.com', 587)
            mail_server.ehlo()
            mail_server.starttls()
            mail_server.login(self.sender, self.__password)
            msg = """Subject:{0}\n{1}""".format(subject, message)
            mail_server.sendmail(self.sender, receiver, msg)
            mail_server.close()
        except smtplib.SMTPException:
            pass
        self.lock.release()
        print('Released Email Lock')
