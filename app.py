from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, SelectField
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
    # email = db.Column(db.String(80), nullable=False)
    # level = db.Column()

# Define the Visitor model
class Visitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lastName = db.Column(db.String(50), nullable=False)
    firstName = db.Column(db.String(50), nullable=False)
    companyName = db.Column(db.String(100))
    visitorId = db.Column(db.String(20))
    arrivingDate = db.Column(db.String(20))
    arrivingTime = db.Column(db.String(20))
    departingDate = db.Column(db.String(20))
    departingTime = db.Column(db.String(20))
    vehicleNo = db.Column(db.String(20))
    visitorNo = db.Column(db.String(20))
    phoneNumber = db.Column(db.String(20))
    emailAddress = db.Column(db.String(120))
    requester = db.Column(db.String(50))
    apointmentNo = db.Column(db.String(20))
    remarks = db.Column(db.String(255))
    history = db.Column(db.String(255))
    status = db.Column(db.String(20))

# Route for the form
@app.route('/newvisitor/<string:visitor_id>', methods=['GET', 'POST'])
def new_visitor(visitor_id):
    visitor = Visitor.query.filter_by(visitorNo=visitor_id).first()

    if request.method == 'POST':
        # Get form data using request.form.get to avoid BadRequestKeyError
        last_name = request.form.get('lastName', '')
        first_name = request.form.get('firstName', '')
        company_name = request.form.get('companyName', '')
        visitor_id = request.form.get('VisitorId', '')
        arriving_date = request.form.get('arrivingDate', '')
        arriving_time = request.form.get('arrivingTime', '')
        departing_date = request.form.get('departingDate', '')
        departing_time = request.form.get('departingTime', '')
        vehicle_no = request.form.get('vehicleNo', '')
        visitor_no = request.form.get('visitorNo', '')
        phone_number = request.form.get('phoneNumber', '')
        email_address = request.form.get('emailAddress', '')
        requester = request.form.get('requester', '')
        appointment_no = request.form.get('apointmentNo', '')
        remarks = request.form.get('remarks', '')
        history = request.form.get('history', '')
        status = request.form.get('statusbtn', '')  # Assuming status is captured from the button

        # Create a new Visitor object
        new_visitor = Visitor(
            lastName=last_name,
            firstName=first_name,
            companyName=company_name,
            visitorId=visitor_id,
            arrivingDate=arriving_date,
            arrivingTime=arriving_time,
            departingDate=departing_date,
            departingTime=departing_time,
            vehicleNo=vehicle_no,
            visitorNo=visitor_no,
            phoneNumber=phone_number,
            emailAddress=email_address,
            requester=requester,
            apointmentNo=appointment_no,
            remarks=remarks,
            history=history,
            status=status
        )

        # Add the new visitor to the database
        try:
            db.session.add(new_visitor)
            db.session.commit()
        except Exception as e:
            print(f"Error committing to database: {e}")

        return redirect(url_for('dashboard'))

    return render_template('newvisitor.html', visitor=visitor)

@app.route('/visitor_list')
def visitor_list():
    visitors = Visitor.query.all()
    return render_template('visitor_list.html', visitors=visitors)

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    email = EmailField(validators=[
                             InputRequired(), Length(min=8, max=40)], render_kw={"placeholder": "E-mail"})

    level = SelectField('Level', choices=[('beginner', 'Beginner'), ('intermediate', 'Intermediate'), ('advanced', 'Advanced')])

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
    visitors = Visitor.query.all()
    visitor_ids = [visitor.visitorId for visitor in visitors]
    return render_template('dashboard.html', visitors=visitors, visitor_ids=visitor_ids)

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

# @app.route('/newVisitor')
# def newVisitor():
#     return render_template('newvisitor.html')

if __name__ == "__main__":
    app.run(debug=True)
