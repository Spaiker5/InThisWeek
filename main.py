from flask import Flask, render_template, request, session, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from forms import *
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///events.db'

init_app(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    notification_day = db.Column(db.String(10), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)

    def __init__(self, username, email, password, notification_day):
        self.username = username
        self.email = email
        self.notification_day = notification_day

        # Generate password hash using bcrypt
        self.set_password(password)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')


# Define the Event model
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.Date, nullable=False)
    notify_on_event_day = db.Column(db.Boolean, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('events', lazy=True))


# Set up scheduler
scheduler = BackgroundScheduler()


@app.before_request
def initialize_scheduler():
    if not scheduler.running:
        create_tables()
        initialize_app()
        scheduler.start()


def create_tables():
    with app.app_context():
        db.create_all()


def initialize_app():
    create_tables()
    with app.app_context():
        existing_user = User.query.filter_by(email='test@example.com').first()
        if existing_user:
            existing_user.username = 'testuser'
            existing_user.set_password('password')  # Use the set_password method to update the password hash
            existing_user.notification_day = 'Monday'  # Set the notification day
            db.session.commit()
        else:
            user = User(username='testuser', email='test@example.com', password='password', notification_day='Monday')
            db.session.add(user)
            db.session.commit()


def load_user(user_id):
    return User.query.get(int(user_id))


@app.context_processor
def inject_current_user():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        return {'current_user': user}
    return {}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        # Create a new user object with the form data
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            notification_day=form.notification_day.data  # Add the notification_day parameter
        )

        try:
            # Add the new user to the database
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('An error occurred during registration.', 'error')
            print(str(e))
            return redirect(url_for('register'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if session.get('user_id'):
        return redirect(url_for('dashboard'))

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'error')

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect(url_for('login'))

    user = load_user(session['user_id'])

    if user is not None:
        events = user.events
        return render_template('dashboard.html', user=user, events=events)
    else:
        flash('User not found. Please log in.', 'error')
        return redirect(url_for('login'))


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in to view your profile.', 'error')
        return redirect('/login')

    user_id = session['user_id']
    user = User.query.get(user_id)

    if user:
        return render_template('profile.html', user=user)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('index'))


@app.route('/create_event', methods=['GET', 'POST'])
def create_event():
    if 'user_id' not in session:
        flash('Please log in to view your profile.', 'error')
        return redirect('/login')

    user_id = session['user_id']
    user = User.query.get(user_id)

    form = CreateEventForm()

    if request.method == 'POST':
        # Process the form submission
        if form.validate_on_submit():
            # Save the event to the database
            event = Event(
                title=form.title.data,
                description=form.description.data,
                date=datetime.strptime(form.date.data, '%Y-%m-%d').date(),
                user_id=session['user_id'],
                notify_on_event_day=form.notify_on_event_day.data

            )
            db.session.add(event)
            db.session.commit()

            flash('Event created successfully!', 'success')
            return redirect(url_for('dashboard'))

    return render_template('create_event.html', form=form)


@app.route('/delete_event/<int:event_id>', methods=['POST'])
def delete_event(event_id):
    if not session.get('user_id'):
        return redirect(url_for('login'))

    event = Event.query.get(event_id)
    if event and event.user_id == session['user_id']:
        db.session.delete(event)
        db.session.commit()
        flash('Event deleted successfully!', 'success')

    return redirect(url_for('dashboard'))


@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data
        confirm_password = form.confirm_password.data

        # Retrieve the logged-in user from the database
        # ...

        # Check if the current password matches the user's stored password
        if bcrypt.check_password_hash(user.password, current_password):
            # Check if the new password and confirm password match
            if new_password == confirm_password:
                # Update the user's password
                user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                db.session.commit()
                flash('Password changed successfully!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('New password and confirm password do not match.', 'error')
        else:
            flash('Invalid current password.', 'error')

    return render_template('change_password.html', form=form)


@app.route('/change-email', methods=['GET', 'POST'])
def change_email():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        new_email = form.new_email.data

        # Retrieve the logged-in user from the database
        # ...

        # Update the user's email
        user.email = new_email
        db.session.commit()
        flash('Email changed successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('change_email.html', form=form)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data

        user = User.query.filter_by(email=email).first()

        if user:
            token = generate_token()
            user.reset_token = token
            db.session.commit()
            send_password_reset_email(user)
            flash('Password reset email sent!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid email address.', 'error')

    return render_template('forgot_password.html', form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user:
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        confirm_password = form.confirm_password.data

        if password != confirm_password:
            flash('New password and confirm password do not match.', 'error')
            return render_template('reset_password.html', form=form, token=token)
        else:
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')
            user.reset_token = None
            db.session.commit()
            flash('Password reset successful! You can now log in with your new password.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', form=form, token=token)


if __name__ == '__main__':
    app.run(debug=True)
