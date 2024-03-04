from flask import Flask, request, redirect, render_template, flash, session
from flask_session import Session
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
import os
import re
import bcrypt

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
socketio = SocketIO(app)


def create_database():
    # Connect to SQLite database (creates if not exists)
    conn = sqlite3.connect('cybersecurity_reports.db')
    cursor = conn.cursor()

    # Create Users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Users (
        UserID INTEGER PRIMARY KEY,
        Username TEXT NOT NULL,
        Email TEXT NOT NULL,
        Password TEXT NOT NULL,
        Role TEXT NOT NULL DEFAULT 'user',  -- Default role is 'user'
        ProfilePicture TEXT,
        UNIQUE(Username, Email)
    )
    ''')

    # Create Roles table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Roles (
        RoleID INTEGER PRIMARY KEY,
        Name TEXT NOT NULL UNIQUE
    )
    ''')

    # Insert default roles
    cursor.execute("INSERT OR IGNORE INTO Roles (Name) VALUES ('admin')")
    cursor.execute("INSERT OR IGNORE INTO Roles (Name) VALUES ('user')")

    # Create UserRoles table for many-to-many relationship between users and roles
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS UserRoles (
        UserRoleID INTEGER PRIMARY KEY,
        UserID INTEGER NOT NULL,
        RoleID INTEGER NOT NULL,
        FOREIGN KEY (UserID) REFERENCES Users(UserID),
        FOREIGN KEY (RoleID) REFERENCES Roles(RoleID)
    )
    ''')

    # Create Reports table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Reports (
        ReportID INTEGER PRIMARY KEY,
        Title TEXT NOT NULL,
        Description TEXT,
        CreationDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        LastModifiedDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UserID INTEGER NOT NULL,
        FOREIGN KEY (UserID) REFERENCES Users(UserID)
    )
    ''')

    # Create Screenshots table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Screenshots (
        ScreenshotID INTEGER PRIMARY KEY,
        ImageURL TEXT NOT NULL,
        Description TEXT,
        ReportID INTEGER NOT NULL,
        FOREIGN KEY (ReportID) REFERENCES Reports(ReportID)
    )
    ''')

    # Create Comments table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Comments (
        CommentID INTEGER PRIMARY KEY,
        Content TEXT NOT NULL,
        CreationDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UserID INTEGER NOT NULL,
        ReportID INTEGER NOT NULL,
        FOREIGN KEY (UserID) REFERENCES Users(UserID),
        FOREIGN KEY (ReportID) REFERENCES Reports(ReportID)
    )
    ''')

    # Create Tags table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Tags (
        TagID INTEGER PRIMARY KEY,
        Name TEXT NOT NULL,
        Description TEXT
    )
    ''')

    # Create ReportTags table for many-to-many relationship
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ReportTags (
        ReportTagID INTEGER PRIMARY KEY,
        ReportID INTEGER NOT NULL,
        TagID INTEGER NOT NULL,
        FOREIGN KEY (ReportID) REFERENCES Reports(ReportID),
        FOREIGN KEY (TagID) REFERENCES Tags(TagID)
    )
    ''')

    # Commit changes and close connection
    conn.commit()
    conn.close()

# Placeholder function to add a new user to the database

# Function to hash password


def hash_password(password):
    salt = b'$2b$12$yz23e0hUe.IxMBFnatOFcu'
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# Function to add a new user to the database


def add_user(username, email, password):
    hashed_password = hash_password(password)

    conn = sqlite3.connect('cybersecurity_reports.db')
    cursor = conn.cursor()

    cursor.execute('''
    INSERT INTO Users (Username, Email, Password) VALUES (?, ?, ?)
    ''', (username, email, hashed_password))
    conn.commit()
    conn.close()

# Function to get a user by username from the database


def get_user_by_username(username):
    conn = sqlite3.connect('cybersecurity_reports.db')
    cursor = conn.cursor()
    user = cursor.execute(
        'SELECT * FROM Users WHERE Username = ?', (username,)).fetchone()
    conn.close()
    return user


def validate_password(password):
    # Password must be at least 8 characters long
    if len(password) < 8:
        return False

    # Password must contain at least one uppercase letter
    if not re.search("[A-Z]", password):
        return False

    # Password must contain at least one lowercase letter
    if not re.search("[a-z]", password):
        return False

    # Password must contain at least one digit
    if not re.search("[0-9]", password):
        return False

    # Password must contain at least one special character
    if not re.search("[!@#$%^&*()_+}{\":;?/><.,]", password):
        return False

    return True


@app.route('/')
def dashboard():
    if 'username' in session:
        return render_template("dashboard.html", user_name=session['username'])
    flash('Kindly Login to access the dashboard', 'error')
    return redirect('/login')


@app.route('/view')
def viewAll():
    if 'username' in session:
        conn = sqlite3.connect('cybersecurity_reports.db')
        cursor = conn.cursor()
        # Fetch report from the database based on the report_id
        cursor.execute(
            "SELECT * FROM Reports ")
        report = cursor.fetchall()

        ids, titles = [], []

        for reports in report:
            ids.append(reports[0])
            titles.append(reports[1])

        if report:
            # print(report)
            return render_template("viewAll.html", ids=ids, titles=titles, size=len(ids), user=session['username'])
        else:
            flash('Report not found!', 'error')
            return redirect('/')
    else:
        flash('Kindly Login to access the dashboard', 'error')
        return redirect('/login')


@app.route('/view/<int:report_id>')
def view(report_id):
    conn = sqlite3.connect('cybersecurity_reports.db')
    cursor = conn.cursor()
    # Fetch report from the database based on the report_id
    cursor.execute(
        "SELECT * FROM Reports WHERE ReportID = ?", (report_id,))
    report = cursor.fetchone()

    if report:
        title = report[1]
        body = report[2].replace('\n', '<br>')
        return render_template("view.html", title=title, body=body)
    else:
        flash('Report not found!', 'error')
        return redirect('/')
    # else:
    #     flash('Kindly Login to access the dashboard', 'error')
    #     return redirect('/login')


@app.route('/create', methods=['GET', 'POST'])
def create():
    if 'username' in session:
        if request.method == 'POST':
            title = request.form['title']
            description = request.form['description']
            if not title:
                flash('Title required to Proceed.', 'error')
                return render_template("create.html", user=session['username'])

            conn = sqlite3.connect('cybersecurity_reports.db')
            cursor = conn.cursor()

            # Insert data into the Reports table
            cursor.execute('''
                INSERT INTO Reports (Title, Description, UserID)
                VALUES (?, ?, ?)
            ''', (title, description, session['username']))  # Replace 1 with the actual UserID

            # Commit changes and close connection
            conn.commit()
            conn.close()

            flash('Succesfully Saved', 'success')

        # If it's a GET request, render the form
        return render_template("create.html", user=session['username'])
    flash('Kindly Login to access the dashboard', 'error')
    return redirect('/login')


@app.route('/live')
def live():
    return render_template("live.html", user='Samuel')
    flash('Kindly Login to access the dashboard', 'error')
    return redirect('/login')


@socketio.on('join')
def handle_join(user):
    room = user
    join_room(room)


@socketio.on('send_data_event')
def send_data(data):
    room = data.get('user')
    emitted_data = data.get('data')
    if room and emitted_data:
        emit('update_para', emitted_data, room=room)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'username' in session:
        return redirect('/')
    if request.method == 'POST':
        # Get user input from the form
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Validate password
        if not validate_password(password):
            flash('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.', 'error')
            return redirect(request.url)

        try:
            # Check if username already exists
            conn = sqlite3.connect('cybersecurity_reports.db')
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Users WHERE Username=?", (username,))
            existing_username = cursor.fetchone()

            # Check if email already exists
            cursor.execute("SELECT * FROM Users WHERE Email=?", (email,))
            existing_email = cursor.fetchone()

            if existing_username:
                flash('Username already exists. Please choose a different one.', 'error')
                return redirect(request.url)

            if existing_email:
                flash(
                    'Email address already exists. Please use a different one.', 'error')
                return redirect(request.url)

            add_user(username, email, password)

            flash('User successfully registered. You can now log in.', 'success')
            # return redirect('/login')

        except Exception as e:
            print(e)
            flash('An error occurred. Please try again later.', 'error')
            return redirect(request.url)

    # If the request method is GET, render the signup form
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect('/')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user_by_username(username)
        if user and user[3] == hash_password(password):
            session['username'] = username
            flash('Logged in successfully!', 'success')
            # Redirect to dashboard page after successful login
            # return redirect('/')
        else:
            flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)  # Clear the username from session
    flash('Logged out successfully!', 'success')
    return redirect('/login')


if __name__ == '__main__':
    create_database()
    app.run(debug=True)
