#This class creates a SQLite database with two tables:
#auth for storing usernames and password hashes and 
#accounts for storing registered accounts associated with usernames.
#It provides methods to 
#[]register user
#[]update user
#[]delete user
#[]authenticate user
#[]add account 
#[]get accounts
#[]update accounts
#[]delete accounts
#[] and close the database connection.


import sqlite3
from hashlib import sha512

class PasswordManagerDB:
    def __init__(self, db_name='password_manager.db'):
        self.conn = sqlite3.connect(db_name)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        # table 1 auth
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth (               
                username TEXT PRIMARY KEY,
                password_hash TEXT
            )
        ''')

        # table 2 accounts 
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                account_name TEXT,
                password TEXT,
                FOREIGN KEY (username) REFERENCES auth(username)
            )
        ''')
        self.conn.commit()



    def register_user(self, username, password):
        password_hash = sha512(password.encode()).hexdigest()
        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO auth (username, password_hash)
                VALUES (?, ?)
            ''', (username, password_hash))
            self.conn.commit()

            #changeme
            print(f"User '{username}' registered successfully!")
        except sqlite3.IntegrityError:
            #changeme
            print(f"Username '{username}' already exists. Try a different username.")


    def update_user(self, old_username, new_username, new_password):
        cursor = self.conn.cursor()
        if old_username != new_username:
            cursor.execute('''
                UPDATE auth SET username = ? WHERE username = ?
            ''', (new_username, old_username))
            cursor.execute('''
                UPDATE accounts SET username = ? WHERE username = ?
            ''', (new_username, old_username))
        password_hash = sha512(new_password.encode()).hexdigest()
        cursor.execute('''
            UPDATE auth SET password_hash = ?
            WHERE username = ?
        ''', (password_hash, new_username))
        self.conn.commit()
        #changeme
        print(f"User '{old_username}' updated to '{new_username}'.")

    def delete_user(self, username):
        cursor = self.conn.cursor()
        cursor.execute('''
            DELETE FROM auth WHERE username = ?
        ''', (username,))
        cursor.execute('''
            DELETE FROM accounts WHERE username = ?
        ''', (username,))
        self.conn.commit()
        #changeme
        print(f"User '{username}' and associated accounts deleted.")

    def authenticate_user(self, username, password):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT password_hash FROM auth WHERE username = ?
        ''', (username,))
        result = cursor.fetchone()
        if result:
            stored_password_hash = result[0]
            password_hash = sha512(password.encode()).hexdigest()
            if stored_password_hash == password_hash:
                #changeme
                print(f"User '{username}' authenticated successfully!")
                return True
            #changeme
        print("Authentication failed. Please check your username and password.")
        return False


    def add_account(self, username, account_name, password):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO accounts (username, account_name, password)
            VALUES (?, ?, ?)
        ''', (username, account_name, password))
        self.conn.commit()
        #cahngeme
        print(f"Account '{account_name}' added for user '{username}'.")

    def get_accounts(self, username):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT account_name, password FROM accounts WHERE username = ?
        ''', (username,))
        accounts = cursor.fetchall()
        if accounts:
            return accounts
        else:
            #changeme
            print("No accounts found for this user.")
            return []
        
    def update_account(self, username, account_name, new_password):
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE accounts SET password = ?
            WHERE username = ? AND account_name = ?
        ''', (new_password, username, account_name))
        self.conn.commit()
        #changeme
        print(f"Account '{account_name}' updated for user '{username}'.")

    def delete_account(self, username, account_name):
        cursor = self.conn.cursor()
        cursor.execute('''
            DELETE FROM accounts
            WHERE username = ? AND account_name = ?
        ''', (username, account_name))
        self.conn.commit()
        #changeme
        print(f"Account '{account_name}' deleted for user '{username}'.")


    def close_connection(self):
        self.conn.close()

# # Usage example:
# if __name__ == "__main__":
#     db = PasswordManagerDB()

#     db.register_user('user1', 'password123')
#     db.register_user('user2', 'pass456')

#     db.authenticate_user('user1', 'password123')
#     db.update_user('user1', 'password123', 'new_password')
#     db.authenticate_user('user2', 'pass_wrong')

#     print("User 'user1' accounts after user update:")

#     db.delete_user('user2')

#     print(db.get_accounts('user1'))

#     db.add_account('user1', 'example.com', 'example_password')
#     db.add_account('user2', 'bank.com', 'bank_password')

#     print("User 1's accounts:")
#     print(db.get_accounts('user1'))

#     print("User 2's accounts:")
#     print(db.get_accounts('user2'))

#     db.close_connection()
