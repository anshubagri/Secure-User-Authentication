from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import bcrypt
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_PATH = 'database.db'

# Initialize DB once at startup
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            dob TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password BLOB NOT NULL
        )
        ''')
        conn.commit()

# Explicitly call DB initialization when app starts
init_db()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    name = request.form['name']
    dob = request.form['dob']
    email = request.form['email']
    password = request.form['password'].encode('utf-8')
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (name, dob, email, password) VALUES (?, ?, ?, ?)",
                           (name, dob, email, hashed))
            conn.commit()
            return redirect(url_for('registration_success'))
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Email already registered'})

@app.route('/registration-success')
def registration_success():
    return render_template('success.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password'].encode('utf-8')

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

    if user:
        if bcrypt.checkpw(password, user[4]):
            session['user'] = user[1]
            return jsonify({'success': True, 'message': 'Login successful', 'redirect': url_for('login_success')})
        else:
            return jsonify({'success': False, 'message': 'Wrong password'})
    else:
        return jsonify({'success': False, 'message': 'Email not found'})

@app.route('/login-success')
def login_success():
    if 'user' in session:
        return render_template("success_login.html")
    else:
        return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
