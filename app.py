from flask import Flask, render_template, request, url_for, redirect, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from dotenv import load_dotenv
from flask_mail import Mail, Message
import random
# from flask_login import LoginManager


# Initialize Flask app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

load_dotenv()
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER")
app.config["MAIL_PORT"] = os.environ.get("MAIL_PORT")
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS")

# Initialize Flask-Mail
mail = Mail(app)

# # Initialize database and login manager
db = SQLAlchemy(app)
# login_manager = LoginManager() 
# login_manager.init_app(app)
# login_manager.login_view = "login"

# # User model
class Detail(db.Model):
    __tablename__ = "detail"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    # Relationship with logs
    logs = db.relationship('Log', backref='user', lazy=True)

class Log(db.Model):
    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date(), nullable=False)
    timein = db.Column(db.Time(), nullable=False)
    timeout = db.Column(db.Time(), nullable=False)
    task = db.Column(db.String(), nullable=False)
    description = db.Column(db.String())
    hours = db.Column(db.Float(), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('detail.id'), nullable=False, index=True)

    __table_args__ = (db.UniqueConstraint('date', 'user_id', name='unique_date_user'),)

# Create database
with app.app_context():
    db.create_all()

#  user for Flask-Login
# @login_manager.user_loader
# def load_user(user_id):
#     return Detail.query.get(int(user_id))

# # Home route
@app.route('/')
def welcome():
    username = session.get('username')  # Get the username from the session
    return render_template('welcome.html', username=username)


# # Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if username or email is already used
        if Detail.query.filter_by(username=username).first():
            msg = 'Username already exists.'
            return render_template('register.html', msg=msg)
        if Detail.query.filter_by(email=email).first():
            msg = 'Email already exists.'
            return render_template('register.html', msg=msg)

        # Generate a random 6-digit OTP
        otp = str(random.randint(100000, 999999))

        # Store temp user data and OTP in session
        session['temp_user'] = {'username': username, 'email': email, 'password': password}
        session['otp'] = otp

        # Send the OTP email
        try:
            otp_msg = Message(
                subject='OTP Verification - LogTracker',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email],
                body=f"Hi {username},\n\nYour OTP for registration is: {otp}\n\nPlease enter this to complete registration."
            )
            mail.send(otp_msg)
            return redirect(url_for('verify_otp'))
        except Exception as e:
            msg = 'Failed to send OTP. Please try again later.'
            print("Email error:", e)
            return render_template('register.html', msg=msg)

    return render_template('register.html', msg=msg)

# # OTP verification route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    msg = ''
    temp_user = session.get('temp_user')

    # No temp user in session? Redirect to register
    if not temp_user:
        return redirect(url_for('register'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        actual_otp = session.get('otp')

        if entered_otp == actual_otp:
            # Create and save the user
            hashed_password = generate_password_hash(temp_user['password'])
            new_user = Detail(
                username=temp_user['username'],
                email=temp_user['email'],
                password=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()

            # Clear session
            session.pop('temp_user', None)
            session.pop('otp', None)

            msg = 'Registration successful. Please log in.'
            return render_template('welcome.html', msg=msg, username=temp_user['username'])
        else:
            msg = 'Invalid OTP. Please try again.'

    return render_template('verify_otp.html', msg=msg)


# # Forgot password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    msg = ''
    if request.method == 'POST':
        email = request.form['email']
        user = Detail.query.filter_by(email=email).first()
        if user:
            otp = str(random.randint(100000, 999999))
            session['reset_email'] = email
            session['reset_otp'] = otp
            try:
                msg_body = f"Hi {user.username},\n\nYour OTP for password reset is: {otp}"
                otp_msg = Message(subject='Password Reset OTP - LogTracker',
                                  sender=app.config['MAIL_USERNAME'],
                                  recipients=[email],
                                  body=msg_body)
                mail.send(otp_msg)
                return redirect(url_for('verify_reset_otp'))
            except Exception as e:
                print("Email error:", e)
                msg = 'Failed to send OTP. Try again later.'
        else:
            msg = 'Email not registered.'

    return render_template('forgot_password.html', msg=msg)

# # OTP verification for password reset
@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    msg = ''
    if not session.get('reset_email'):
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        actual_otp = session.get('reset_otp')
        if entered_otp == actual_otp:
            return redirect(url_for('reset_password'))
        else:
            msg = 'Invalid OTP. Try again.'
    
    return render_template('verify_reset_otp.html', msg=msg)


# # Reset password route
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    msg = ''
    email = session.get('reset_email')
    if not email:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            msg = 'Passwords do not match.'
            return render_template('reset_password.html', msg=msg)

        user = Detail.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password)
            db.session.commit()

            # Clean up session
            session.pop('reset_email', None)
            session.pop('reset_otp', None)

            msg = 'Password reset successful. Please log in.'
            return render_template('login.html', msg=msg)
        else:
            msg = 'User not found.'
    
    return render_template('reset_password.html', msg=msg)


# login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    
    # Check if a user is already logged in
    if 'username' in session:
        return render_template('welcome.html', msg=msg, username=session['username'])

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = Detail.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            msg = 'Login successful.'
            return render_template('welcome.html', msg=msg, username=username)
        else:
            msg = 'Invalid username or password.'
            return render_template('login.html', msg=msg)
    
    return render_template('login.html', msg=msg)

# # Logout route
@app.route("/logout")
def logout():
    if 'username' in session:
        session.pop('username', None)  # Clear the session
        msg = 'You have been logged out.'
    else:
        msg = 'You are not logged in.'
    return render_template('welcome.html', msg=msg, username=None)   
    
    
@app.route('/addlog', methods=['POST', 'GET'])
def addlog():
    msg = ''
    if 'username' in session:
        user = Detail.query.filter_by(username=session['username']).first()
        if not user:  # Check if user exists
            session.pop('username', None)  # Clear invalid session
            return redirect(url_for('login'))

        if request.method == 'POST':
            try:
                # Parse and validate the date input
                log_date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
                current_date = datetime.now().date()

                # Check if the date is in the future
                if log_date > current_date:
                    msg = 'The date cannot be in the future. Please enter a valid date.'
                    return render_template('addlog.html', msg=msg, username=user.username)

            except ValueError:
                # Handle invalid date formats or non-existent dates (e.g., 31-02-2025)
                msg = 'Invalid date. Please enter a valid date in the format YYYY-MM-DD.'
                return render_template('addlog.html', msg=msg, username=user.username)

            # Check if a log for the given date already exists
            log = Log.query.filter_by(date=log_date, user_id=user.id).first()
            if log:
                msg = 'A log for this date already exists. Please choose a different date.'
                return render_template('addlog.html', msg=msg, username=user.username)

            # Parse and validate time inputs
            try:
                log_timein = datetime.strptime(request.form['timein'], '%H:%M').time()
                log_timeout = datetime.strptime(request.form['timeout'], '%H:%M').time()

                # Ensure timeout is later than timein
                if log_timeout <= log_timein:
                    msg = 'Timeout must be later than Timein. Please enter valid times.'
                    return render_template('addlog.html', msg=msg, username=user.username)

                # Calculate hours worked
                timein_datetime = datetime.combine(log_date, log_timein)
                timeout_datetime = datetime.combine(log_date, log_timeout)
                hours_worked = (timeout_datetime - timein_datetime).total_seconds() / 3600  # Convert seconds to hours

            except ValueError:
                msg = 'Invalid time format. Please enter time in HH:MM format.'
                return render_template('addlog.html', msg=msg, username=user.username)

            # Create and save the new log
            new_log = Log(
                date=log_date,
                timein=log_timein,
                timeout=log_timeout,
                task=request.form['task'],
                description=request.form['description'],
                hours=hours_worked,  # Automatically calculated hours
                user_id=user.id
            )
            db.session.add(new_log)
            db.session.commit()
            msg = 'Log added successfully.'
            return redirect(url_for('viewlog'))

        return render_template('addlog.html', username=user.username, msg=msg)
    else:
        return redirect(url_for('login'))
    
 
@app.route('/viewlog', methods=['GET'])
def viewlog():
    if 'username' in session:
        user = Detail.query.filter_by(username=session['username']).first()
        if not user:  # Check if user exists
            session.pop('username', None)  # Clear invalid session
            return redirect(url_for('login'))

        logs = Log.query.filter_by(user_id=user.id).all()
        return render_template('viewlog.html', log=logs, username=user.username, count=len(logs))
    else:
        return redirect(url_for('login'))
    

@app.route('/updatelog/<int:id>', methods=['GET', 'POST'])
def updatelog(id):
    msg = ''
    
    # Check if the user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))

    # Get the currently logged-in user
    user = Detail.query.filter_by(username=session['username']).first()
    if not user:
        return redirect(url_for('login'))

    # Fetch the log by ID
    log = Log.query.filter_by(id=id).first()

    # Check if the log exists and belongs to the logged-in user
    if not log or log.user_id != user.id:
        msg = 'You are not authorized to access this log.'
        return render_template('error.html', msg=msg)  # Render an error page or redirect

    if request.method == 'POST':
        try:
            # Parse and validate the date input
            log_date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
            current_date = datetime.now().date()

            # Check if the date is in the future
            if log_date > current_date:
                msg = 'The date cannot be in the future. Please enter a valid date.'
                return render_template('addlog.html', l=log, username=user.username, msg=msg)

            log.date = log_date

        except ValueError:
            msg = 'Invalid date. Please enter a valid date in the format YYYY-MM-DD.'
            return render_template('addlog.html', l=log, username=user.username, msg=msg)

        # Parse and validate time inputs
        try:
            timein_input = request.form.get('timein', '').strip()
            timeout_input = request.form.get('timeout', '').strip()

            if not timein_input or not timeout_input:
                msg = 'Timein and Timeout fields cannot be empty.'
                return render_template('addlog.html', l=log, username=user.username, msg=msg)

            log_timein = datetime.strptime(timein_input, '%H:%M').time()
            log_timeout = datetime.strptime(timeout_input, '%H:%M').time()

            # Ensure timeout is later than timein
            if log_timeout <= log_timein:
                msg = 'Timeout must be later than Timein. Please enter valid times.'
                return render_template('addlog.html', l=log, username=user.username, msg=msg)

            # Calculate hours worked
            timein_datetime = datetime.combine(log.date, log_timein)
            timeout_datetime = datetime.combine(log.date, log_timeout)
            hours_worked = (timeout_datetime - timein_datetime).total_seconds() / 3600  # Convert seconds to hours

            log.timein = log_timein
            log.timeout = log_timeout
            log.hours = hours_worked  # Automatically calculated hours

        except ValueError:
            msg = 'Invalid time format. Please enter time in HH:MM format.'
            return render_template('addlog.html', l=log, username=user.username, msg=msg)

        # Update other fields
        log.task = request.form['task']
        log.description = request.form['description']

        # Commit changes to the database
        db.session.commit()
        msg = 'Log updated successfully.'
        return redirect(url_for('viewlog'))

    return render_template('addlog.html', l=log, username=user.username, msg=msg)


@app.route('/deletelog/<int:id>',methods=['GET'])
def deletelog(id):
    log=Log.query.filter_by(id=id).first()
    db.session.delete(log)
    db.session.commit()
    print('log deleted successfully')
    return redirect(url_for('viewlog'))


if __name__ == "__main__":
    app.run(debug=True)