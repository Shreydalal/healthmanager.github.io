from flask import Flask, render_template, request, redirect, url_for, flash, session  # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
from flask_mail import Mail, Message  # type: ignore
from itsdangerous import URLSafeTimedSerializer, SignatureExpired  # type: ignore
from random import randint  # type: ignore
from datetime import datetime, timedelta  # type: ignore
from email_validator import validate_email, EmailNotValidError  # type: ignore
from flask_pymongo import PyMongo  # type: ignore
import hashlib  # type: ignore

# Initialize Flask app
app = Flask(__name__, template_folder='template')
app.secret_key = '9099544377'

# Configure email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'x718114@gmail.com'
app.config['MAIL_PASSWORD'] = 'vsrfiworhqitklls'
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# Configure MongoDB
app.config['MONGO_URI'] = 'mongodb://localhost:27017/healthdb'
mongo = PyMongo(app)

otp_store = {}

@app.route('/')
def landing_page():
    return render_template('landing_page.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = mongo.db.users.find_one({"username": username})
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session.pop('update_required', None)
            if not user.get('medical_info'):
                flash('Please update your medical information.', 'info')
                return redirect(url_for('update_medical_info'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials, please try again.', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))

        if mongo.db.users.find_one({"username": username}):
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('signup'))

        if mongo.db.users.find_one({"email": email}):
            flash('Email already exists. Please use a different email.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        new_user = {
            "username": username,
            "email": email,
            "password": hashed_password,
            "medical_info": None
        }
        mongo.db.users.insert_one(new_user)

        session['username'] = username
        session['update_required'] = True
        flash('Account created successfully! Please update your details.', 'success')
        return redirect(url_for('update_medical_info'))

    return render_template('signup.html')

@app.route('/update_medical_info', methods=['GET', 'POST'])
def update_medical_info():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({"username": session['username']})
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        age = request.form.get('age')
        weight = request.form.get('weight')
        height = request.form.get('height')

        medical_info = {
            "age": int(age),
            "weight": float(weight),
            "height": float(height)
        }
        mongo.db.users.update_one({"username": session['username']}, {"$set": {"medical_info": medical_info}})

        session.pop('update_required', None)
        flash('Medical information updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('update_medical_info.html', user=user)

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({"username": session['username']})
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    medical_info = user.get('medical_info')
    if not medical_info:
        flash('Please update your medical information.', 'info')
        return redirect(url_for('update_medical_info'))

    weight = medical_info.get('weight')
    height_cm = medical_info.get('height')

    bmi = None
    bmi_category = None
    bmi_risk_color = None
    if weight and height_cm:
        height_m = height_cm / 100
        bmi = weight / (height_m ** 2)

        if bmi < 18.5:
            bmi_category = "Underweight"
            bmi_risk_color = "text-yellow-500"
        elif 18.5 <= bmi < 24.9:
            bmi_category = "Normal weight"
            bmi_risk_color = "text-green-500"
        elif 25 <= bmi < 29.9:
            bmi_category = "Overweight"
            bmi_risk_color = "text-orange-500"
        elif 30 <= bmi < 34.9:
            bmi_category = "Obesity (Class-I)"
            bmi_risk_color = "text-red-500"
        elif 35 <= bmi < 39.9:
            bmi_category = "Obesity (Class-II)"
            bmi_risk_color = "text-red-500"
        else:
            bmi_category = "Obesity (Class-III)"
            bmi_risk_color = "text-red-500"

    return render_template(
        'dashboard.html',
        medical_info=medical_info,
        bmi=bmi,
        bmi_category=bmi_category,
        bmi_risk_color=bmi_risk_color
    )

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', ' ').strip()

        try:
            validate_email(email)
        except EmailNotValidError:
            flash('Invalid email address.', 'danger')
            return redirect(url_for('forgot_password'))

        if not email:
            flash('Email field is required.', 'danger')
            return redirect(url_for('forgot_password'))

        user = mongo.db.users.find_one({"email": email})
        if user:
            otp = randint(100000, 999999)
            otp_store[email] = {
                'otp': otp,
                'expiration': datetime.now() + timedelta(minutes=5)
            }

            msg = Message('Password Reset OTP', sender='x718114@gmail.com', recipients=[email])
            msg.body = f"Your OTP for password reset is: {otp}"
            try:
                mail.send(msg)
                flash('OTP has been sent to your email.', 'success')
                return redirect(url_for('reset_password', email=email))
            except Exception as e:
                flash('Failed to send OTP. Please try again later.', 'danger')
                return redirect(url_for('forgot_password'))
        else:
            flash('No user found with that email.', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<email>/', methods=['GET', 'POST'])
def reset_password(email):
    if request.method == 'POST':
        otp_entered = request.form['otp']
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check OTP validity
        otp_info = otp_store.get(email)
        if not otp_info:
            flash('OTP not generated or expired.', 'danger')
            return redirect(url_for('forgot_password'))

        if otp_info['expiration'] < datetime.now():
            flash('OTP has expired.', 'danger')
            del otp_store[email]
            return redirect(url_for('forgot_password'))

        if otp_info['otp'] != int(otp_entered):
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect(url_for('reset_password', email=email))

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', email=email))

        # Update password in the database
        hashed_password = generate_password_hash(new_password)
        mongo.db.users.update_one({"email": email}, {"$set": {"password": hashed_password}})

        # Remove OTP from the store after successful use
        del otp_store[email]

        flash('Your password has been successfully reset. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', email=email)

@app.route('/delete_user/<string:username>', methods=['GET', 'POST'])
def delete_user(username):
    if 'username' not in session or session['username'] != username:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))

    # Fetch user from MongoDB collection
    user = mongo.db.users.find_one({'username': username})
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        password = request.form.get('password')

        if not password or password.strip() == '':
            flash('Password is required.', 'danger')
            return redirect(url_for('delete_user', username=username))

        # Check if the provided password matches the user's stored hashed password
        if check_password_hash(user['password'], password):
            try:
                # Delete associated medical info
                mongo.db.medical_info.delete_many({'user_id': user['_id']})
                
                # Delete user
                mongo.db.users.delete_one({'_id': user['_id']})
                
                session.clear()  # Clear the session
                flash(f'User {user["username"]} has been deleted.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                app.logger.error(f"Error deleting user {username}: {e}")  # Log the error
                flash('An error occurred while deleting the user.', 'danger')
        else:
            flash('Incorrect password. Account deletion failed.', 'danger')

    # Render a confirmation form if method is GET or password is incorrect
    return render_template('confirm_delete.html', username=username)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)  # Remove the username from the session
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
