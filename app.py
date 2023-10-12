from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
import os
import sqlite3
from createDB import create_database
import bcrypt  # for hashing

app = Flask(__name__)
app.secret_key = 'securesecret!!!'

# Configure the upload folder and allowed extensions
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to check if the file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    db = sqlite3.connect('users.db')
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    db.close()

# Initialize the database if it doesn't exist
if not os.path.exists('users.db'):
    create_database()
    print('schema created')
    init_db()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the password before storing it in the database
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db = sqlite3.connect('users.db')
        cur = db.cursor()
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        db.commit()
        db.close()
        
        flash('Registration successful. You can now log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = sqlite3.connect('users.db')
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        db.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
            session['username'] = username

            flash('Login successful.')
            return redirect(url_for('profile'))
        else:
            flash('Login failed. Check your username and password.')

    return render_template('login.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' in session:
        # Check if the user has uploaded a file
        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file uplaoded')
                return redirect(request.url)

            file = request.files['file']

            # If the user does not select a file, the browser submits an empty part without a filename
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                flash('File successfully uploaded')

        return render_template('profile.html')
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)


# TODO

## App
# - *Secure* admin panel with user management
#  - Overview of users currently logged in
#  - Overview of all users
#  - Enable/Disable users  

## Additional stuff!!
# User Authentication  - session management and user sessions
# Form Validation - WTForms
# Logging - elastic 
# Error handeling - 404, 500 and other erros
# Security Header - stuff
# resellience -  database N' stuff
# File upload - Secure file upload
# Nginx - set it up yo with https
# User account management - forgot password, change password, delete account
# code cleanup
# frontend......


## Additional security stuff
# Prevent CSRF attacks
# rate limiting
# csp
# safe session
# secure cookies
# secure headers
# firewall
# session timeout
# Troll password 