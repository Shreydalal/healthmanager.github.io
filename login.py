from flask import Flask, render_template, request, redirect, url_for, flash, session  # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
from flask_sqlalchemy import SQLAlchemy# type: ignore
from flask_mail import Mail, Message# type: ignore
from itsdangerous import URLSafeTimedSerializer, SignatureExpired# type: ignore
from flask_migrate import Migrate# type: ignore
from random import randint# type: ignore
from datetime import datetime, timedelta# type: ignore
from email_validator import validate_email, EmailNotValidError# type: ignore
import hashlib# type: ignore


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

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_database1.db'  # SQLite file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy and Migrate
db = SQLAlchemy(app)
migrate = Migrate(app, db)
otp_store = {}

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    medical_info = db.relationship('MedicalInfo', back_populates='user', uselist=False)
    
    def delete(self):
        # Deleting related medical information before deleting user
        if self.medical_info:
            db.session.delete(self.medical_info)
        db.session.delete(self)
        db.session.commit()
    
    
class MedicalInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    age = db.Column(db.Integer)
    weight = db.Column(db.Float)
    height = db.Column(db.Float)
    user = db.relationship('User', back_populates='medical_info')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user exists and password is correct
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            session.pop('update_required', None)  # Clear update flag if exists
            if not user.medical_info:
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

        # Validate inputs
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please use a different email.', 'danger')
            return redirect(url_for('signup'))

        # Hash the password and create a new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Set session and redirect to update medical info
        session['username'] = username
        session['update_required'] = True  # Flag for first-time detail update
        flash('Account created successfully! Please update your details.', 'success')
        return redirect(url_for('update_medical_info'))

    return render_template('signup.html')

@app.route('/update_medical_info', methods=['GET', 'POST'])
def update_medical_info():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Update or create medical information
        age = request.form.get('age')
        weight = request.form.get('weight')
        height = request.form.get('height')
        
        if user.medical_info:
            user.medical_info.age = age
            user.medical_info.weight = weight
            user.medical_info.height = height
        else:
            new_medical_info = MedicalInfo(user_id=user.id, age=age, weight=weight, height=height)
            db.session.add(new_medical_info)
        
        db.session.commit()
        session.pop('update_required', None)  # Remove the flag after updating details
        flash('Medical information updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('update_medical_info.html', user=user)

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
    # Check if medical information is available
    if not user.medical_info:
        flash('Please update your medical information.', 'info')
        return redirect(url_for('update_medical_info'))
    
    # Extract weight and height from medical_info
    weight = user.medical_info.weight  # Accessing attributes directly
    height_cm = user.medical_info.height  # Accessing attributes directly
    
    # Calculate BMI if weight and height are available
    bmi = None
    bmi_category = None
    bmi_risk_color = None
    if weight and height_cm:
        height_m = height_cm / 100  # Convert height to meters
        bmi = weight / (height_m ** 2)
        
        # Determine BMI category and risk level
        if bmi < 18.5:
            bmi_category = "Underweight"
            bmi_risk_color = "text-yellow-500"  # Moderate risk
        elif 18.5 <= bmi < 24.9:
            bmi_category = "Normal weight"
            bmi_risk_color = "text-green-500"  # Low risk
        elif 25 <= bmi < 29.9:
            bmi_category = "Overweight"
            bmi_risk_color = "text-orange-500"  # Increased risk
        elif 30 <= bmi < 34.9:
            bmi_category = "Obesity (Class-I)"
            bmi_risk_color = "text-red-500"  # High risk
        elif 35 <= bmi < 39.9:
            bmi_category = "Obesity (Class-II)"
            bmi_risk_color = "text-red-500"  # High risk
        else:
            bmi_category = "Obesity (Class-III)"
            bmi_risk_color = "text-red-500"  # High risk
    
    return render_template(
        'dashboard.html',
        medical_info=user.medical_info,
        bmi=bmi,
        bmi_category=bmi_category,
        bmi_risk_color=bmi_risk_color
    )

@app.route('/view_users')
def view_users():
    users = User.query.all()
    return '<br>'.join([f"Username: {user.username}, Email: {user.email}" for user in users])

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        print(f"Form data received: {request.form}")
        email = request.form.get('email', ' ').strip()  # Strip any spaces
        print(f"Email received from form: {email}")

        # Validate email format
        try:
            validate_email(email)
        except EmailNotValidError:
            flash('Invalid email address.', 'danger')
            return redirect(url_for('forgot_password'))

        if not email:
            flash('Email field is required.', 'danger')
            return redirect(url_for('forgot_password'))

        # Query case-insensitively
        user = User.query.filter(User.email.ilike(email)).first()
        print(f"Query result: {user}") 
        if user:
            # Generate OTP
            otp = randint(100000, 999999)
            

            otp_store[email] = {
                'otp': otp,
                'expiration': datetime.now() + timedelta(minutes=5)
            }

            # Send OTP via email
            msg = Message('Password Reset OTP', sender='x718114@gmail.com', recipients=[email])
            msg.body = f"Your OTP for password reset is: {otp}"
            try:
                mail.send(msg)
                flash('OTP has been sent to your email.', 'success')
                return redirect(url_for('reset_password', email=email))  # Pass email dynamically
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
        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(new_password)
        db.session.commit()

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

    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        password = request.form.get('password')

        if not password or password.strip() == '':
            flash('Password is required.', 'danger')
            return redirect(url_for('delete_user', username=username))

        # Check if the provided password matches the user's stored hashed password
        if check_password_hash(user.password, password):
            try:
                MedicalInfo.query.filter_by(user_id=user.id).delete()
                db.session.delete(user)  # Deleting the user
                db.session.commit()
                session.clear()  # Clear the session
                flash(f'User {user.username} has been deleted.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('An error occurred while deleting the user.', 'danger')
                app.logger.error(f"Error deleting user {username}: {e}")  # Log the error
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
    app.run(debug=True)
