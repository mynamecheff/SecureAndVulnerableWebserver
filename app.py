import os  # For OS related operations
import uuid  # For generating unique filenames
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, abort
# For securing the filename before storing it
from werkzeug.utils import secure_filename
# For handling file size limit
from werkzeug.exceptions import RequestEntityTooLarge
from flask_sqlalchemy import SQLAlchemy  # For database operations
import bcrypt  # For hashing passwords
from datetime import timedelta  # For session timeout
from flask_limiter import Limiter  # For rate limiting
import logging  # For logging -  not currently used
from flask_wtf.csrf import CSRFProtect  # For CSRF protection
import bleach  # For sanitizing user input
from flask_talisman import Talisman  # For CSP
from sqlalchemy.exc import IntegrityError  # For handling duplicate usernames

app = Flask(__name__)
app.secret_key = 'securesecret!!!'

app.logger.setLevel(logging.INFO)
app.logger.addHandler(logging.StreamHandler())

csrf = CSRFProtect(app)
limiter = Limiter(app)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['SESSION_COOKIE_NAME'] = 'notacøøkie'
app.secret_key = os.urandom(24)

app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.permanent_session_lifetime = timedelta(minutes=30)

# Replace with your database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)


talisman = Talisman(app, content_security_policy={
    'default-src': "'self'",
    'style-src': ["'self'", 'https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css', 'sha384-HtMZLkYo+pR5/u7zCzXxMJP6QoNnQJt1qkHM0EaOPvGDIzaVZbmYr/TlvUZ/sKAg'],
    'script-src': "'self' 'unsafe-inline'",
    'frame-ancestors': "'none'"
})


# Function to check if the file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@limiter.request_filter
def get_remote_address():
    return request.remote_addr


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def enc_error(e):
    return render_template('500.html'), 500


class User(db.Model):
    __tablename__ = 'user'  # Explicitly set the table name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_enabled = db.Column(db.Boolean, default=True)


def is_valid_username(username):
    if 4 <= len(username) <= 20:
        if username.isalnum() or '_' in username:
            if not username.startswith('_') and not username.endswith('_'):
                return True
    return False


def is_valid_password(password):
    if len(password) >= 8:
        if any(char.isupper() for char in password):
            if any(char.islower() for char in password):
                if any(char.isdigit() for char in password):
                    return True
    return False


@app.route('/')
def home():
    return render_template('home.html')


@limiter.limit("5 per minute", key_func=get_remote_address)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = bleach.clean(request.form['username'])
        password = bleach.clean(request.form['password'])

        if not is_valid_username(username):
            flash('Invalid username. Please choose another username.')
            return redirect(request.url)

        if not is_valid_password(password):
            flash('Invalid password. Please choose a stronger password.')
            return redirect(request.url)

        is_admin = False
        is_enabled = True

        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt(15))

        user = User(username=username, password=hashed_password,
                    is_admin=is_admin, is_enabled=is_enabled)

        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful. You can now log in.')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username is already taken. Please choose another username.')
            return redirect(request.url)

    return render_template('register.html')


@limiter.limit("5 per minute", key_func=get_remote_address)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = bleach.clean(request.form['username'])
        password = bleach.clean(request.form['password'])

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password) and user.is_enabled:
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
                if len(file.read()) > app.config['MAX_CONTENT_LENGTH']:
                    flash(
                        'File size exceeds the 10 MB limit. Please upload a smaller file.')
                    return redirect(request.url)
                else:
                    filename = str(uuid.uuid4()) + \
                        secure_filename(file.filename)
                    file.save(os.path.join(
                        app.config['UPLOAD_FOLDER'], filename))
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
        user = User.query.filter_by(username=session['username']).first()
        if user:
            g.user = {
                'username': user.username,
                'is_admin': user.is_admin
            }


@app.route('/admin', methods=['GET'])
@admin_required
def admin_panel():
    logged_in_users = [session.get(
        'username')] if 'username' in session else []
    users = User.query.all()
    return render_template('admin_panel.html', users=users, logged_in_users=logged_in_users)


@app.route('/admin/enable_disable/<int:user_id>', methods=['POST'])
def enable_disable_user(user_id):
    if g.user is not None and g.user.get('is_admin'):
        user = User.query.get(user_id)
        if user:
            user.is_enabled = not user.is_enabled
            db.session.commit()
            flash(
                f'User has been {"enabled" if user.is_enabled else "disabled"}.')
    else:
        flash('Access denied. You must be an admin to access this page.')
    return redirect('/admin')

# Maybe use this for honeypot?!
def is_unsafe_path(path):
    return any(part in path for part in ('root', 'directory', 'test'))


@app.route('/<path:requested_path>')
def serve_page(requested_path):
    if is_unsafe_path(requested_path):
        return render_template('/troll.html')
    else:
        abort(404)


if __name__ == '__main__':
    app.run(debug=True)
    db.create_all()
