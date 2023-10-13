import sqlite3

# Create the SQLite database and tables if they don't exist
def create_database():
    db = sqlite3.connect('users.db')
    cursor = db.cursor()

    # Create the users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL,
            is_enabled INTEGER NOT NULL
        )
    ''')

    db.commit()
    db.close()

if __name__ == '__main__':
    create_database()
