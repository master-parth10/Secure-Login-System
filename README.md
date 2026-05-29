from flask import Flask, request, redirect, session, render_template_string
from flask_bcrypt import Bcrypt
import sqlite3
import pyotp
import re

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_this'

bcrypt = Bcrypt(app)


# DATABASE SETUP

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        secret TEXT
    )
    ''')

    conn.commit()
    conn.close()

init_db()


# INPUT VALIDATION

def valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)


def valid_password(password):
    return len(password) >= 6


# HOME PAGE

@app.route('/')
def home():
    if 'user' in session:
        return f"""
        <h2>Welcome, {session['user']}!</h2>
        <a href='/logout'>Logout</a>
        """
    return """
    <h2>Secure Login System</h2>
    <a href='/register'>Register</a><br><br>
    <a href='/login'>Login</a>
    """


# REGISTER

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        # Input Validation
        if not username or not email or not password:
            return "All fields are required"

        if not valid_email(email):
            return "Invalid email"

        if not valid_password(password):
            return "Password must be at least 6 characters"

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Generate 2FA Secret
        secret = pyotp.random_base32()

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()

            # Parameterized Query (SQL Injection Protection)
            c.execute(
                'INSERT INTO users (username, email, password, secret) VALUES (?, ?, ?, ?)',
                (username, email, hashed_password, secret)
            )

            conn.commit()
            conn.close()

            return f"""
            Registration Successful!<br><br>
            Your 2FA Secret Key:<br>
            <b>{secret}</b><br><br>
            Add this secret in Google Authenticator app.
            <br><br>
            <a href='/login'>Go to Login</a>
            """

        except sqlite3.IntegrityError:
            return "Username or Email already exists"

    return render_template_string('''
    <h2>Register</h2>
    <form method="POST">
        Username:<br>
        <input type="text" name="username"><br><br>

        Email:<br>
        <input type="email" name="email"><br><br>

        Password:<br>
        <input type="password" name="password"><br><br>

        <button type="submit">Register</button>
    </form>
    ''')


# LOGIN

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        otp = request.form['otp']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()

        # Parameterized Query
        c.execute('SELECT password, secret FROM users WHERE username = ?', (username,))
        user = c.fetchone()

        conn.close()

        if user:
            stored_password = user[0]
            secret = user[1]

            # Verify Password
            if bcrypt.check_password_hash(stored_password, password):

                # Verify OTP
                totp = pyotp.TOTP(secret)

                if totp.verify(otp):
                    session['user'] = username
                    return redirect('/')
                else:
                    return "Invalid OTP"

            else:
                return "Invalid Password"

        else:
            return "User not found"

    return render_template_string('''
    <h2>Login</h2>
    <form method="POST">
        Username:<br>
        <input type="text" name="username"><br><br>

        Password:<br>
        <input type="password" name="password"><br><br>

        OTP (Google Authenticator):<br>
        <input type="text" name="otp"><br><br>

        <button type="submit">Login</button>
    </form>
    ''')

# LOGOUT

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')


# RUN APP


if __name__ == '__main__':
    app.run(debug=True)
