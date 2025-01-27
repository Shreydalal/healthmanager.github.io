from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify  # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
from flask_mail import Mail, Message  # type: ignore
from itsdangerous import URLSafeTimedSerializer, SignatureExpired  # type: ignore
from random import randint  # type: ignore
from datetime import datetime, timedelta  # type: ignore
from email_validator import validate_email, EmailNotValidError  # type: ignore
from flask_pymongo import PyMongo  # type: ignore
import hashlib  # type: ignore
from werkzeug.utils import secure_filename
from typing import Optional
import os
import json
import re
import traceback
import requests


# Initialize Flask app
app = Flask(__name__, template_folder='template')
app.secret_key = '9099544377'


# Configure email
app.config['MAIL_USERNAME'] = "MAIL_USERNAME"
app.config['MAIL_PASSWORD'] = "MAIL_PASSWORD"
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# Configure MongoDB
app.config['MONGO_URI'] = 'mongodb://localhost:27017/healthdb'
mongo = PyMongo(app)

app.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

BASE_API_URL = "https://api.langflow.astra.datastax.com"
LANGFLOW_ID = "fadc231c-beec-4dfa-aec3-91d744a8d4b1"
FLOW_ID = "f5c80e54-49c5-48b9-aeee-896ff907ed57"
APPLICATION_TOKEN = "Your application token"
ENDPOINT = FLOW_ID  # You can set a specific endpoint name in the flow settings

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
                print(e)
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

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        flash('Please log in to access your profile.', 'danger')
        return redirect(url_for('login'))
    
    user = mongo.db.users.find_one({"username": session['username']})
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        mobile_no = request.form.get('mobile_no')

        # Validate inputs
        if not name or not email or not mobile_no:
            flash('All fields are required.', 'danger')
            return redirect(url_for('profile'))
        
        # Check for email uniqueness
        email_exists = mongo.db.users.find_one({"email": email, "_id": {"$ne": user["_id"]}})
        if email_exists:
            flash('Email is already in use by another user.', 'danger')
            return redirect(url_for('profile'))
        
        user_name_exists = mongo.db.users.find_one({"name": name , "_id": {"$ne": user["_id"]}})
        if user_name_exists:
            flash('Username is already in use by another user.', 'danger')
            return redirect(url_for('profile'))

        # Update user information
        mongo.db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"username": name, "email": email, "mobile_no": mobile_no}}
        )

        session['username'] = name  # Update session username if changed
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('profile.html', user=user)

@app.route('/update_profile_picture', methods=['POST'])
def update_profile_picture():
    if 'username' not in session:
        flash('Please log in to update your profile picture.', 'danger')
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({"username": session['username']})
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            mongo.db.users.update_one(
                {"_id": user["_id"]},
                {"$set": {"profile_picture": file_path}}
            )

            flash('Profile picture updated successfully!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid file type. Please upload an image.', 'danger')

    return redirect(url_for('profile'))


# Function to run the flow
def run_flow(message: str) -> dict:
    api_url = f"https://api.langflow.astra.datastax.com/lf/fadc231c-beec-4dfa-aec3-91d744a8d4b1/api/v1/run/f5c80e54-49c5-48b9-aeee-896ff907ed57?stream=false"
    payload = {
        "input_value": message,
        "output_type": "chat",
        "input_type": "chat",
    }
    headers = {
    "Authorization": f"Bearer {APPLICATION_TOKEN}",  # Replace with your actual API key
    "Content-Type": "application/json"
    }
    try:
        response = requests.post(api_url, json=payload, headers=headers)
        response.raise_for_status()  # Raise exception for HTTP errors
        return response.json()  # Parse JSON response
    except requests.exceptions.RequestException as e:
        print(f"RequestException: {str(e)}")  # Log the exception
        traceback.print_exc()
        return {"error": f"Request failed: {str(e)}"}

def clean_text(text: str) -> str:
    # Remove special characters like #, * (excluding ** for bold)
    text = re.sub(r"(?<!\*)[\\#*](?!\*)", "", text).strip()
    # Replace **text** with <strong>text</strong> for bold formatting
    text = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", text)
    return text

# In-memory chat history (to simulate session state in Flask)
chat_history = []

@app.route("/bot", methods=["GET", "POST"])
def home():
    global chat_history

    if request.method == "POST":
        try:
            data = request.get_json()
            # print(f"Received JSON: {data}")  # Log incoming JSON

            if not data or not data.get("message", "").strip():
                return jsonify({"error": "Please enter a message"}), 400

            message = data["message"]
            # print(f"User Message: {message}")  # Log user's message

            # Call run_flow and log its response
            response = run_flow(message)
            # print(f"Langflow API Response: {response}")

            if "error" in response:
                # print(f"Langflow API Error: {response['error']}")
                return jsonify({"error": response["error"]}), 500

            # Extract and clean response
            response_text = (
                response.get("outputs", [{}])[0]
                .get("outputs", [{}])[0]
                .get("results", {})
                .get("message", {})
                .get("text", "No response text found")
            )

            cleaned_response_text = clean_text(response_text)

            if not cleaned_response_text:
                cleaned_response_text = "Sorry, I couldn't understand that."

            # print(f"Cleaned Response Text: {cleaned_response_text}")  # Log cleaned response

            return jsonify({"bot": cleaned_response_text})  # Return bot's response

        except Exception as e:
            # print(f"Unexpected Error: {str(e)}")  # Log unexpected errors
            traceback.print_exc()
            return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

    # Render a simple page for GET requests
    return render_template("chat_bot.html", chat_history=chat_history)



if __name__ == '__main__':
    app.run(debug=True, threaded=True)
