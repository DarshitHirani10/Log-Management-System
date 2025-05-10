from flask import Flask, render_template, request, url_for, redirect, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from dotenv import load_dotenv
# from flask_login import LoginManager


# Initialize Flask app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

load_dotenv()
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
# print(app.config["SECRET_KEY"])
 
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
@app.route('/register', methods=['POST', 'GET'])
def register():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if username or email already exists
        user = Detail.query.filter_by(username=username).first()
        email_exists = Detail.query.filter_by(email=email).first()

        if user:
            msg = 'Username already exists. Please choose a different username.'
            return render_template('register.html', msg=msg)
        elif email_exists:
            msg = 'Email already exists. Please use a different email.'
            return render_template('register.html', msg=msg)
        else:
            # Create a new user
            hashed_password = generate_password_hash(password)
            new_user = Detail(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            msg = 'Registration successful. Please log in.'
            return render_template('welcome.html', username=username, msg=msg)
    return render_template('register.html', msg=msg)

# # Login route
@app.route('/login',methods=['POST','GET'])
def login():
    msg=''
    if 'username' in session:
        msg='you are already logged in'
        return render_template('welcome.html',username=session['username'],msg=msg)
    else:
        if request.method == 'POST':
            user=Detail.query.filter_by(username=request.form['username']).first()
            if user:
                try:
                    if check_password_hash (user.password, request.form['password']):
                        msg=' login successful'
                        session['username']=user.username
                        return render_template('welcome.html',username=user.username,msg=msg)
                    else:
                        msg='Wrong password!'
                        return render_template('login.html',msg=msg)
                except Exception as e:
                    msg='Wrong password!'
                    return render_template('login.html',msg=msg)
                    
            else:
                msg='User doesn\'t exits!'
            return render_template('login.html',msg=msg)
        else:
            return render_template('login.html',msg=msg)
        

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
            log = Log.query.filter_by(date=request.form['date'], user_id=user.id).first()
            if log:
                msg = 'A log for this date already exists. Please choose a different date.'
                return render_template('addlog.html', msg=msg, username=user.username)
            else:
                # Parse date and time inputs correctly
                log_date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
                log_timein = datetime.strptime(request.form['timein'], '%H:%M').time()
                log_timeout = datetime.strptime(request.form['timeout'], '%H:%M').time()

                new_log = Log(
                    date=log_date,
                    timein=log_timein,
                    timeout=log_timeout,
                    task=request.form['task'],
                    description=request.form['description'],
                    hours=float(request.form['hours']),
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
    

@app.route('/updatelog/<int:id>',methods=['GET','POST'])
def updatelog(id):
    msg = ''
    log=Log.query.filter_by(id=id).first()
    user=Detail.query.filter_by(id=log.user_id).first()
    if request.method == 'POST':
        log.date=datetime.strptime(request.form['date'],'%Y-%m-%d').date()

        try:
            log.timein=datetime.strptime(request.form['timein'],'%H:%M:%S').time()
        except ValueError:
            log.timein=datetime.strptime(request.form['timein'],'%H:%M').time()
        try:
            log.timeout=datetime.strptime(request.form['timeout'],'%H:%M:%S').time()
        except ValueError:
            log.timeout=datetime.strptime(request.form['timeout'],'%H:%M').time()

        log.task=request.form['task']
        log.description=request.form['description']
        log.hours=float(request.form['hours'])
        log.user_id=log.user_id
        db.session.commit()
        msg = 'Log added successfully'
        return redirect(url_for('viewlog'))
    return render_template('addlog.html',l=log,username=user.username,msg=msg)

@app.route('/deletelog/<int:id>',methods=['GET'])
def deletelog(id):
    log=Log.query.filter_by(id=id).first()
    db.session.delete(log)
    db.session.commit()
    print('log deleted successfully')
    return redirect(url_for('viewlog'))


if __name__ == "__main__":
    app.run(debug=True)