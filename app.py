# Importing necessary modules and libraries
from flask import Flask, render_template, request, redirect, url_for, session ,flash                                                                                       # request (for handling HTTP requests), redirect and url_for (for redirecting to other routes or URLs),                                                                                     # session (for managing user sessions), and flash (for displaying messages to the user).
import sqlite3 
import os
import bcrypt 
import json 
import requests
from PIL import Image, ImageDraw, ImageFont
import random 
import io 
import base64 
from flask_mail import Mail, Message 

app = Flask(__name__) 
app.secret_key = os.urandom(24) 
app.static_url_path = '/static'

DATABASE = "database.db" 
RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY') 


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

     
    cursor.execute("PRAGMA table_info(students)")
    columns = cursor.fetchall()
    phone_number_exists = any(column[1] == 'phone_number' for column in columns)
    new_phone_number_request_exists = any(column[1] == 'new_phone_number_request' for column in columns)


    if not phone_number_exists:
       
        cursor.execute("ALTER TABLE students ADD COLUMN phone_number TEXT")

    if not new_phone_number_request_exists:
       
        cursor.execute("ALTER TABLE students ADD COLUMN new_phone_number_request TEXT")

   
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

   
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            student_id TEXT NOT NULL,
            email TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            new_phone_number_request TEXT
        )
    ''')

    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS teachers (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            employee_id TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')

    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY,
            course_code TEXT NOT NULL,
            course_name TEXT NOT NULL
        )
    ''')
   
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS teacher_student_assignment (
            id INTEGER PRIMARY KEY,
            teacher_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            FOREIGN KEY (teacher_id) REFERENCES teachers (id),
            FOREIGN KEY (student_id) REFERENCES students (id)
                   
        )
    ''')

    
    cursor.execute("SELECT * FROM users WHERE role='admin'")
    admin_user = cursor.fetchone()

    # If there is no admin user, create one with default credentials
    if not admin_user:
        admin_username = "admin"
        admin_password = "admin"
        admin_role = "admin"

        hashed_admin_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                       (admin_username, hashed_admin_password, admin_role))

    conn.commit()
    conn.close()




@app.route('/')

def welcome():
    return render_template('welcome.html')


def index():
    return redirect(url_for('login')) 


def generate_captcha():
    captcha = ''.join(random.choice('0123456789') for _ in range(4)) # Generate a random 4-digit CAPTCHA
    return captcha


def verify_recaptcha(recaptcha_response):
    secret_key = "Secret_key"
    data = {
        'secret': secret_key,
        'response': recaptcha_response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    result = response.json()
    return result.get('success', False)



def generate_captcha_image(text):
    width, height = 180, 150  

    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)

    font = ImageFont.truetype("static/fonts/montserrat/Montserrat-BlackItalic.ttf", 30) 
    draw.text((100, 40), text, font=font, fill=(0, 0, 0))

    for _ in range(100):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = x1 + random.randint(0, 180)
        y2 = y1 + random.randint(0, 180)
        draw.line((x1, y1, x2, y2), fill=(0, 0, 0))

    image_io = io.BytesIO()
    image.save(image_io, "PNG")
    image_io.seek(0)
    return image_io

def generate_recovery_token():
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(32))




@app.route('/login', methods=['GET', 'POST'])
def login():
    captcha = ''
    captcha_image_io = None
    error_message = ""

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        recaptcha_response = request.form.get('g-recaptcha-response')

        if not verify_recaptcha(recaptcha_response):
            flash('reCAPTCHA verification failed. Please try again.', category='error')
            return redirect(url_for('login'))

        else:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchone()
            conn.close()

            if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
                session['username'] = user[1]
                session['is_admin'] = user[3] == 'admin'
                return redirect(url_for('home'))  
            else:
                error_message = "Invalid username, password, or captcha."

    if captcha_image_io is None:
        captcha = generate_captcha()
        captcha_image_io = generate_captcha_image(captcha)
        session['captcha'] = captcha

    if captcha_image_io is None:
        captcha_image_io = generate_captcha_image("DefaultCaptcha")  

    captcha_image_base64 = base64.b64encode(captcha_image_io.getvalue()).decode('utf-8')

    return render_template('login.html', captcha=captcha, captcha_image=captcha_image_base64, error_message=error_message)
    return redirect(url_for('login'))


@app.route('/user/<int:user_id>')

def user_details(user_id):
    # Connect to the database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()

    if user:
        if user[3] == 'student':
            cursor.execute("SELECT * FROM students WHERE username=?", (user[1],))
            additional_info = cursor.fetchone()
        elif user[3] == 'teacher':
            cursor.execute("SELECT * FROM teachers WHERE username=?", (user[1],))
            additional_info = cursor.fetchone()
        else:
            additional_info = None
        
        conn.close() 

        print("User details fetched:", user, additional_info) 

        return render_template('user_details.html', user=user, additional_info=additional_info) 
    else:
        return "User not found" 
    return redirect(url_for('login'))


@app.route('/student_profile', methods=['GET', 'POST'])
def student_profile():
    if 'username' in session:
        username = session['username']

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM students WHERE username=?", (username,))
        student_profile = cursor.fetchone()

        cursor.execute("SELECT new_phone_number_request FROM students WHERE username=?", (username,))
        pending_request = cursor.fetchone()

        is_admin = session.get('is_admin', False)

        if pending_request and is_admin:
            pending_phone_number_request = pending_request[0]
            return render_template('students.html', student_profile=student_profile, pending_phone_number_request=pending_phone_number_request)
        
        elif request.method == 'POST':
            new_password = request.form['new_password']
            if new_password:
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed_password, username))
                conn.commit()
                flash('Password changed successfully!', 'success')

            new_phone_number = request.form.get('new_phone_number')

            if new_phone_number:
                cursor.execute("UPDATE students SET phone_number=?, new_phone_number_request=NULL WHERE username=?", (new_phone_number, username))
                conn.commit()
                flash('Phone number changed successfully!', 'success')

            cursor.execute("SELECT phone_number FROM students WHERE username=?", (username,))
            updated_phone_number = cursor.fetchone()[0]
            student_profile_dict = {
                'username': student_profile[1],
                'first_name': student_profile[2],
                'last_name': student_profile[3],
                'student_id': student_profile[4],
                'email': student_profile[5],
                'phone_number': updated_phone_number  
            }
            return render_template('students.html', student_profile=student_profile_dict)
        else:
            cursor.execute("SELECT phone_number FROM students WHERE username=?", (username,))
            phone_number = cursor.fetchone()[0]
            student_profile_dict = {
                'username': student_profile[1],
                'first_name': student_profile[2],
                'last_name': student_profile[3],
                'student_id': student_profile[4],
                'email': student_profile[5],
                'phone_number': phone_number  
            }
            return render_template('students.html', student_profile=student_profile_dict)

        conn.close()

    return "User not logged in"
    return redirect(url_for('login'))




@app.route('/submit_phone_number_request', methods=['POST'])
def submit_phone_number_request():
    if 'username' in session and request.method == 'POST':
        username = session['username']
        new_phone_number = request.form['new_phone_number']

        # Connect to the database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("UPDATE students SET new_phone_number_request=? WHERE username=?", (new_phone_number, username))
        
        cursor.execute("UPDATE students SET phone_number=? WHERE username=?", (new_phone_number, username))

        conn.commit()
        conn.close()

        flash('Phone number change request submitted successfully!', 'success')
        return redirect(url_for('student_profile'))

    return redirect(url_for('login'))



@app.route('/handle_phone_number_request', methods=['POST'])
def handle_phone_number_request():
    if 'username' in session and session['is_admin'] and request.method == 'POST':
        username = request.form['username']
        new_phone_number = request.form['new_phone_number']
        action = request.form['action']  

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        if action == 'approve':
            cursor.execute("UPDATE students SET phone_number=?, new_phone_number_request=NULL WHERE username=?", (new_phone_number, username))
            flash('Phone number change request approved successfully!', 'success')
        elif action == 'reject':
            cursor.execute("UPDATE students SET new_phone_number_request=NULL WHERE username=?", (username,))
            flash('Phone number change request rejected!', 'warning')

        conn.commit()
        conn.close()

        return redirect(url_for('student_profile'))

    return redirect(url_for('login'))

@app.route('/home')

def home():
    if 'username' in session:
        is_admin = session.get('is_admin', False) 

        user_data = {
            'courses': ['Maths', 'Science', 'Arts']
        }

        return render_template('home.html', username=session['username'], is_admin=is_admin, user_data=user_data) 
    return redirect(url_for('login')) # If no user is logged in, redirect to the login page



@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' in session and session['is_admin']:
        if request.method == 'POST':
            action = request.form.get('action', '')

            if action == 'add_user':
                new_username = request.form['new_username']
                new_password = request.form['new_password']
                role = request.form['role']
                first_name = request.form['first_name']
                last_name = request.form['last_name']
                email = request.form['email']
                additional_fields = None

                if role == 'student':
                    student_id = request.form['student_id']
                    additional_fields = (student_id,)
                elif role == 'teacher':
                    employee_id = request.form['employee_id']
                    additional_fields = (employee_id,)

                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

                with sqlite3.connect(DATABASE) as conn:
                    cursor = conn.cursor()

                    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                                   (new_username, hashed_password, role))

                    if additional_fields:
                        cursor.execute(f"INSERT INTO {role}s (username, first_name, last_name, {'student_id' if role == 'student' else 'employee_id'}, email) VALUES (?, ?, ?, ?, ?)",
                                       (new_username, first_name, last_name, *additional_fields, email))

                    conn.commit()  

                flash('User added successfully', 'success')  
                return redirect(url_for('admin'))  

            elif action == 'add_course':
                course_code = request.form['course_code']
                course_name = request.form['course_name']

                with sqlite3.connect(DATABASE) as conn:
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO courses (course_code, course_name) VALUES (?, ?)", (course_code, course_name))
                    conn.commit()

                flash('Course added successfully', 'success') 
                return redirect(url_for('admin')) 

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, first_name, last_name FROM teachers")
            teachers = cursor.fetchall()
            print("Teachers:", teachers)

            cursor.execute("SELECT id, first_name, last_name FROM students")
            students = cursor.fetchall()
            print("Students",students)

        return render_template('admin.html', teachers=teachers, students=students)  

    return redirect(url_for('login'))  



@app.route('/assign_students', methods=['GET', 'POST'])
def assign_students():
    if 'is_admin' in session and session['is_admin']:
        if request.method == 'POST':
            teacher_id = request.form['teacher_id']
            student_ids = request.form.getlist('student_ids')
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            for student_id in student_ids:
                cursor.execute("INSERT INTO teacher_student_assignment (teacher_id, student_id) VALUES (?, ?)", (teacher_id, student_id))

            conn.commit()
            conn.close()

            flash('Students assigned successfully', 'success')
            return redirect(url_for('assign_students'))

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT id, name FROM teachers")
        teachers = cursor.fetchall()

        cursor.execute("SELECT id, name FROM students")
        students = cursor.fetchall()

        conn.close()

        return render_template('assign_students.html', teachers=teachers, students=students)

    return "Unauthorized access"
    return redirect(url_for('login'))


@app.route('/logout')

def logout():
    session.clear() 
    return redirect(url_for('login')) 

if __name__ == '__main__':
    init_db() 
    app.run(debug=True, port=5003)
