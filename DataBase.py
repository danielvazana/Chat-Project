import threading
import sqlite3


class DataBase(object):

    def __init__(self):
        """Creates a connection with the database's file and an argument that will use the database.
        If there is no users' table the script creates one."""
        self.connection = None
        self.cursor = None
        self.create_connection('database.db')
        self.create_table()
        self.connection.commit()

    def create_connection(self, db_file):
        """ create a database connection to the SQLite database
            specified by db_file
        :param db_file: database file
        """
        self.connection = sqlite3.connect(db_file, check_same_thread=False)
        self.cursor = self.connection.cursor()

    def create_table(self):
        """ create a table from the create_table_sql statement
        connection: Connection object
        cursor SQL: a CREATE TABLE statement
        """
        create_table_sql = """ CREATE TABLE IF NOT EXISTS users (
                                                name text NOT NULL PRIMARY KEY,
                                                password text NOT NULL,
                                                email text NOT NULL,
                                                list_messages text
                                            ); """
        try:
            self.cursor.execute(create_table_sql)
        except 'Error' as e:
            print(e)

    def add_to_table(self, name, password, email):
        """
        Adds a new user to the database.
        :param name: The name of the new member.
        :param password: The password of the new member.
        :param email: The email of the new member.
        """
        self.cursor.execute('INSERT INTO users VALUES ' + str((name, password, email, '')))
        self.connection.commit()

    def set_in_table(self, name, change, what_to_change):
        """
        "Change user's argument in the database.
        :param name: The name of the user that we want to change something in his details.
        :param change: The value of what we change.
        :param what_to_change: The argument that we change.
        :return:
        """
        sql_command = """
        UPDATE users
        SET {0} = "{1}"
        WHERE name = "{2}"
        """.format(what_to_change, change, name)
        print(sql_command)
        self.cursor.execute(sql_command)

    def delete_from_table(self, name):
        """Deletes an user from the database."""
        sql_command = """
        DELETE FROM users
        WHERE NAME = "{}"
        """.format(name)
        print(sql_command)
        self.cursor.execute(sql_command)
        self.connection.commit()

    def check_in_database(self, name):
        """Checks if user is exists in the database."""
        self.cursor.execute("SELECT rowid FROM users WHERE name = ?", (name,))
        data = self.cursor.fetchall()
        return not (len(data) == 0)

    def get_all_names_from_table(self):
        """Returns all the names of the users."""
        self.cursor.execute('SELECT DISTINCT name from users')
        data = self.cursor.fetchall()
        list_names = []
        for tuple_name in data:
            list_names.append(tuple_name[0])
        return list_names

    def get_value_from_table(self, from_where, value, what_to_find):
        """
        Get an user's variable.
        :param from_where: By which variable to look for.
        :param value: The value of how we looking for the variable.
        :param what_to_find: The variable that we want.
        :return:
        """
        self.cursor.execute("""SELECT {0} FROM users WHERE {1} = "{2}";""".format(what_to_find, from_where, value))
        data = self.cursor.fetchall()
        print(data)
        return data[0][0]


class SyncDataBase(object):

    def __init__(self, ):
        """Creates a database object and Lock and Semaphores for managing the database."""
        self.__data_base = DataBase()
        self.sem = threading.Semaphore(10)
        self.lock = threading.Lock()

    def add_to_data_base(self, name, password, email):
        """Adds new user to the database."""
        self.lock.acquire()
        print('Got Lock')
        for count in range(10):
            self.sem.acquire()
            print('Got' + str(count + 1) + 'Semaphore')
        self.__data_base.add_to_table(name, password, email)
        for count in range(10):
            self.sem.release()
            print('Released' + str(count + 1) + ' Semaphore')
        self.lock.release()
        print('Released Lock')

    def set_to_data_base(self, name, change, what_to_change):
        """Change user's argument in the database. """
        self.lock.acquire()
        print('Got Lock')
        for count in range(10):
            self.sem.acquire()
            print('Got' + str(count + 1) + 'Semaphore')
        self.__data_base.set_in_table(name, change, what_to_change)
        for count in range(10):
            self.sem.release()
            print('Released' + str(count + 1) + ' Semaphore')
        self.lock.release()
        print('Released Lock')

    def read_from_data_base(self, from_where, value, what_to_find):
        """Get an user's argument."""
        self.lock.acquire()
        print('Got Lock')
        self.sem.acquire()
        print('Got Semaphore')
        self.lock.release()
        print('Released Lock')
        argument = self.__data_base.get_value_from_table(from_where, value, what_to_find)
        self.sem.release()
        print('Released Semaphore')
        return argument

    def delete_from_dict(self, key):
        """Deletes an user from the database."""
        self.lock.acquire()
        print('Got Lock')
        for count in range(10):
            self.sem.acquire()
            print('Got' + str(count + 1) + 'Semaphore')
        print(self.__data_base.delete_from_table(key))
        for count in range(10):
            self.sem.release()
            print('Released' + str(count + 1) + ' Semaphore')
        self.lock.release()
        print('Released Lock')

    def check_key_in_database(self, key):
        """Checks if user is exists in the database."""
        self.lock.acquire()
        print('Got Lock')
        self.sem.acquire()
        print('Got Semaphore')
        self.lock.release()
        print('Released Lock')
        checking = self.__data_base.check_in_database(key)
        self.sem.release()
        print('Released Semaphore')
        return checking

    def get_all_user_names(self):
        """Returns all the names of the users."""
        self.lock.acquire()
        print('Got Lock')
        self.sem.acquire()
        print('Got Semaphore')
        self.lock.release()
        print('Released Lock')
        argument = self.__data_base.get_all_names_from_table()
        self.sem.release()
        print('Released Semaphore')
        return argument
