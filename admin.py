import sqlite3

user_id_to_promote = 4

db = sqlite3.connect('users.db')

cur = db.cursor()

cur.execute("SELECT COUNT(*) FROM users WHERE id = ?", (user_id_to_promote,))
user_exists = cur.fetchone()[0]

if user_exists:
    # Update the user's is_admin flag to 1
    cur.execute("UPDATE users SET is_admin = 1 WHERE id = ?",
                (user_id_to_promote,))
    db.commit()
    print(f"User with ID {user_id_to_promote} is now an admin.")
else:
    print(f"User with ID {user_id_to_promote} does not exist.")

# Close the database connection
db.close()

# prob not working rn
