from flask import Flask, render_template, request, redirect, url_for, send_from_directory, abort, flash, session, render_template_string
from markupsafe import escape
import sqlite3
import os
import subprocess

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'ctf_lab.db'
comments = []  # Temporary storage for comments

# Directory settings for each vulnerability
UPLOAD_DIRECTORIES = {
    "command_injection": "flags/command_injection",
    "sqli": "flags/sqli",
    "ssti": "flags/ssti",
    "xss": "flags/xss",
    "uploads": "flags/uploads"
}

# Ensure directories exist
for directory in UPLOAD_DIRECTORIES.values():
    os.makedirs(directory, exist_ok=True)

# Static list of files for IDOR (in a real scenario, this could be in a database)
IDOR_FILES = [
    {"id": 1, "filename": "secret_report1.pdf"},
    {"id": 2, "filename": "secret_report2.pdf"},
    {"id": 3, "filename": "confidential_data3.pdf"}
]

# Helper function for secure path resolution
def secure_filepath(directory, filename):
    base_path = os.path.abspath(directory)
    target_path = os.path.abspath(os.path.join(base_path, filename))
    if not target_path.startswith(base_path):  # Prevent path traversal
        abort(403)
    return target_path

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Route for robots.txt
@app.route('/robots.txt')
def robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt')

# Route for robots.txt
@app.route('/employees.txt')
def employees_txt():
    return send_from_directory(app.static_folder, 'employees.txt')
    
    
# Function to check if input contains `=`
def contains_invalid_characters(input_string):
    return "=" in input_string

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        # Render the Forgot Password page for GET requests
        return render_template('forgot_password.html')

    if request.method == 'POST':
        # Handle POST requests for username verification
        username = request.form['username']
        conn = get_db_connection()

        # Check if the username exists
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user:
            # Vulnerability: Different response for existing vs. non-existing usernames
            flash("User found. OTP sent to your registered email.", "success")
            return render_template('verify_otp.html')

            session['otp'] = "031"  # Hardcoded OTP
            session['username_reset'] = username
        else:
            flash("Username not found. Please try again.", "danger")

        return redirect(url_for('forgot_password'))



@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']

        # Validate the entered OTP
        if 'otp' in session and entered_otp == session['otp']:  # Compare as strings
            flash("OTP verified! You can reset your password.", "success")
            return redirect(url_for('reset_password'))
        else:
            # Vulnerability: No rate-limiting or OTP expiration
            flash("Invalid OTP. Please try again.", "danger")

    return render_template('verify_otp.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    # Ensure the user reached here through the OTP flow
    if 'username_reset' not in session:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password']
        username = session['username_reset']

        # Update the password in the database
        conn = get_db_connection()
        conn.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, username))
        conn.commit()
        conn.close()

        # Clear the session variables
        session.pop('otp', None)
        session.pop('username_reset', None)

        flash("Password reset successfully!", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')


# Login page with SQL Injection and SSTI vulnerabilities
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        # Simulate generic response for both valid and invalid usernames/passwords
        if user and user['password'] == password:
            session['username'] = username
            flash("Successfully logged in!", "success")
            return redirect(url_for('admin'))
        else:
            flash("Invalid username or password", "danger")

        conn.close()

    return render_template('login.html')



# Comment submission (XSS vulnerability)
@app.route('/submit_comment', methods=['POST'])
def submit_comment():
    comment = request.form['comment']
    comments.append(comment)  # Add comment to the in-memory list
    flash("Comment submitted!", "success")
    return redirect(url_for('login'))  # Redirect back to /login to display comments


# Admin page with Command Injection vulnerability
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' not in session:
        return redirect(url_for('login'))

    flag = "CC{Wow_SQLi???}"
    command_output = ""
    if request.method == 'POST':
        cmd = request.form['command']
        try:
            command_output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
            flash("Command executed successfully", "success")
        except subprocess.CalledProcessError as e:
            command_output = e.output
            flash("Command execution failed", "danger")
    return render_template('admin.html', flag=flag, output=command_output)



# Route to display memes with links
@app.route('/memes/')
def meme_list():
    conn = get_db_connection()
    memes = conn.execute('SELECT * FROM files ORDER BY id DESC LIMIT 2').fetchall()
    conn.close()

    return render_template('memes.html', memes=memes)



# Route to serve individual meme by ID
@app.route('/memes/<int:meme_id>')
def serve_meme(meme_id):
    conn = get_db_connection()
    meme = conn.execute('SELECT * FROM files WHERE id = ?', (meme_id,)).fetchone()
    conn.close()

    if meme:
        return render_template('meme_detail.html', meme=meme)
    else:
        abort(404)

      
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
