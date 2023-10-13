import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import sqlite3
from createDB import create_database
import bcrypt
from datetime import timedelta
from flask_limiter import Limiter # Add limiter to code
import logging
from flask_wtf.csrf import CSRFProtect
from wtforms import Form

app = Flask(__name__)
app.secret_key = 'securesecret!!!'

app.logger.setLevel(logging.INFO)
app.logger.addHandler(logging.StreamHandler())



# Configure the upload folder and allowed extensions
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.permanent_session_lifetime = timedelta(minutes=30)  # Set the session lifetime to 30 minutes



# Add Content Security Policy (CSP) header
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net"
    return response


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

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

def is_valid_username(username):
    # Username should be between 4 and 20 characters
    if 4 <= len(username) <= 20:
        # Username should contain only alphanumeric characters and underscores
        if username.isalnum() or '_' in username:
            # Username should not start or end with an underscore
            if not username.startswith('_') and not username.endswith('_'):
                return True
    return False

def is_valid_password(password):
    # Password should be at least 8 characters long
    if len(password) >= 8:
        # Password should contain at least one uppercase letter
        if any(char.isupper() for char in password):
            # Password should contain at least one lowercase letter
            if any(char.islower() for char in password):
                # Password should contain at least one digit
                if any(char.isdigit() for char in password):
                    # Password can contain special characters
                    return True
    return False


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Validate username and password
        if not is_valid_username(username):
            flash('Invalid username. Please choose another username.')
            return redirect(request.url)

        if not is_valid_password(password):
            flash('Invalid password. Please choose a stronger password.')
            return redirect(request.url)
        
        is_admin = 0
        is_enabled = True
        # Hash the password before storing it in the database
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db = sqlite3.connect('users.db')
        cur = db.cursor()
        cur.execute("INSERT INTO users (username, password, is_admin, is_enabled) VALUES (?, ?, ?, ?)", (username, hashed_password, is_admin, is_enabled))
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

        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]) and user[4] == 1:
            session['username'] = username

            flash('Login successful.')
            return redirect(url_for('profile'))
        else:
            flash('Login failed. Check your username and password.')

    return render_template('login.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' in session:
        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file uploaded')
                return redirect(request.url)

            file = request.files['file']

            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)

            if file and allowed_file(file.filename):
                # Generate a unique filename
                filename = str(uuid.uuid4()) + secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                flash('File successfully uploaded')

        return render_template('profile.html')
    else:
        return redirect(url_for('login'))
    

@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(error):
    flash('File size limit exceeded. Please upload a smaller file.')
    return redirect(request.url) 

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

def admin_required(view):
    def wrapped_view(**kwargs):
        if g.user is not None and g.user.get('is_admin'):
            return view(**kwargs)
        flash('Access denied. You must be an admin to access this page.')
        return redirect(url_for('home'))
    return wrapped_view

@app.before_request
def load_user():
    g.user = None
    if 'username' in session:
        db = sqlite3.connect('users.db')
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (session['username'],))
        user = cur.fetchone()
        db.close()
        if user:
            g.user = {
                'username': user[1],
                'is_admin': user[3] == 1 
            }

@app.route('/admin', methods=['GET'])
@admin_required
def admin_panel():
    # Get a list of logged-in users from the session
    logged_in_users = [session.get('username')] if 'username' in session else []

    db = sqlite3.connect('users.db')
    cur = db.cursor()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    db.close()

    return render_template('admin_panel.html', users=users, logged_in_users=logged_in_users)


# enable/disable user
@app.route('/admin/enable_disable/<int:user_id>', methods=['POST'])
def enable_disable_user(user_id):
    if g.user is not None and g.user.get('is_admin'):
        db = sqlite3.connect('users.db')
        cur = db.cursor()
        cur.execute("SELECT is_enabled FROM users WHERE id = ?", (user_id,))
        user_status = cur.fetchone()[0]

        # Toggle the user's status (0 = disabled, 1 = enabled)
        new_status = 1 if user_status == 0 else 0
        cur.execute("UPDATE users SET is_enabled = ? WHERE id = ?", (new_status, user_id))
        db.commit()
        db.close()

        flash(f'User has been {"enabled" if new_status == 1 else "disabled"}.')
    else:
        flash('Access denied. You must be an admin to access this page.')

    return redirect('/admin')


if __name__ == '__main__':
    app.run(debug=True)
