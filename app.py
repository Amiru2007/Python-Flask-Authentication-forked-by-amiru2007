from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class Visitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    last_name = db.Column(db.String(50))
    first_name = db.Column(db.String(50))
    company_name = db.Column(db.String(50))
    visitor_id = db.Column(db.String(20))
    arriving_date = db.Column(db.String(20))
    arriving_time = db.Column(db.String(20))
    departing_date = db.Column(db.String(20))
    departing_time = db.Column(db.String(20))
    vehicle_no = db.Column(db.String(20))
    visitor_no = db.Column(db.String(20))
    phone_number = db.Column(db.String(20))
    email_address = db.Column(db.String(50))
    requester = db.Column(db.String(50))
    appointment_no = db.Column(db.String(20))
    remarks = db.Column(db.String(100))
    history = db.Column(db.String(100))
    status = db.Column(db.String(20))

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/newVisitor')
def newVisitor():
    return render_template('newvisitor.html')

@app.route('/visitor_add', methods=['POST'])
def visitor_add():
    if request.method == 'POST':
        # Retrieve data from the form
        last_name = request.form.get('lastName')
        first_name = request.form.get('firstName')
        company_name = request.form.get('companyName')
        visitor_id = request.form.get('VisitorId')
        arriving_date = request.form.get('arrivingDate')
        arriving_time = request.form.get('arrivingTime')
        departing_date = request.form.get('departingDate')
        departing_time = request.form.get('departingTime')
        vehicle_no = request.form.get('vehicleNo')
        visitor_no = request.form.get('visitorNo')
        phone_number = request.form.get('phoneNumber')
        email_address = request.form.get('emailAddress')
        requester = request.form.get('requester')
        appointment_no = request.form.get('apointmentNo')
        remarks = request.form.get('remarks')
        history = request.form.get('history')
        status = request.form.get('statusbtn', 'Active')  # Default to 'Active' if not provided

        # Create a new Visitor object
        new_visitor = Visitor(
            last_name=last_name,
            first_name=first_name,
            company_name=company_name,
            visitor_id=visitor_id,
            arriving_date=arriving_date,
            arriving_time=arriving_time,
            departing_date=departing_date,
            departing_time=departing_time,
            vehicle_no=vehicle_no,
            visitor_no=visitor_no,
            phone_number=phone_number,
            email_address=email_address,
            requester=requester,
            appointment_no=appointment_no,
            remarks=remarks,
            history=history,
            status=status
        )

        # Add the new visitor to the database and commit the changes
        db.session.add(new_visitor)
        db.session.commit()

        return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
