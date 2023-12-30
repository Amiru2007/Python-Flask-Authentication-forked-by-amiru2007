from flask import Flask, render_template, url_for, redirect, request, jsonify, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, SelectField, TelField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime

app = Flask(__name__)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
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
    email = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    telephoneNo = db.Column(db.String(80), nullable=False)
    level = db.Column(db.String(80), nullable=False)

# Define the Visitor model
class Visitor(db.Model):
    id = db.Column(db.Integer)
    lastName = db.Column(db.String(50), nullable=False)
    firstName = db.Column(db.String(50), nullable=False)
    companyName = db.Column(db.String(100))
    visitorId = db.Column(db.String(20))
    arrivingDate = db.Column(db.String(20))
    arrivingTime = db.Column(db.String(20))
    departingDate = db.Column(db.String(20))
    departingTime = db.Column(db.String(20))
    vehicleNo = db.Column(db.String(20))
    visitorNo = db.Column(db.String(20), primary_key=True)
    phoneNumber = db.Column(db.String(20))
    emailAddress = db.Column(db.String(120))
    requester = db.Column(db.String(50))
    noOfVisitors = db.Column(db.Integer)
    remarks = db.Column(db.String(255))
    history = db.Column(db.String(255))
    status = db.Column(db.String(20))
    requestTime = db.Column(db.String(20))
    approvedTime = db.Column(db.String(20))
    arrivedTime = db.Column(db.String(20))
    departedTime = db.Column(db.String(20))
    # profilePhoto = db.Column(db.LargeBinary, name='profile_photo_upload')

class Approved(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    visitorNo = db.Column(db.String(20), unique=True, nullable=False)
    requester = db.Column(db.String(50))
    approveOrReject = db.Column(db.String(100))
    approver = db.Column(db.String(50))

# Route for the form
@app.route('/newvisitor', methods=['GET', 'POST'])
def new_visitor():
    # visitor = Visitor.query.filter_by(visitorNo=visitor_id).first()

    visitor_code = generate_visitorCode()

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
        noOfVisitors = request.form.get('noOfVisitors', '')
        remarks = request.form.get('remarks', '')
        history = request.form.get('history', '')
        status = request.form.get('statusbtn', '')
        request_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # profilePhoto = request.form.get('profilePhoto', '')  # Assuming status is captured from the button

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
            noOfVisitors=noOfVisitors,
            remarks=remarks,
            history=history,
            status=status,
            requestTime=request_time,
            # profilePhoto=profilePhoto
        )

        # Add the new visitor to the database
        try:
            db.session.add(new_visitor)
            db.session.commit()
        except Exception as e:
            return f"Error committing to database: {e}"

        return redirect(url_for('dashboard'))

    return render_template('newvisitor.html',
                           requester=current_user.username,
                           visitorNo=visitor_code)

def generate_visitorCode():
    # Get the latest code from the database for the current date
    today = datetime.now().strftime('%Y%m%d')
    latest_visitor = Visitor.query.filter(Visitor.visitorNo.like(f'{today}%')).order_by(Visitor.visitorNo.desc()).first()

    if latest_visitor:
        # Increment the counter for the current date
        current_counter = int(latest_visitor.visitorNo[-4:])
        new_counter = str(current_counter + 1).zfill(4)
    else:
        # If it's a new day, start with '0001'
        new_counter = '0001'

    # Combine the date and counter to create the new code
    new_code = f'{today}{new_counter}'
    return new_code

# @app.route('/visitor_list')
# def visitor_list():
#     visitors = Visitor.query.all()
#     return render_template('visitor_list.html', visitors=visitors)

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    email = EmailField(validators=[
                             InputRequired(), Length(min=8, max=40)], render_kw={"placeholder": "E-mail"})

    name = StringField(validators=[
                             InputRequired(), Length(min=8, max=40)], render_kw={"placeholder": "Name"})

    telephoneNo = TelField(validators=[
                             InputRequired(), Length(min=8, max=40)], render_kw={"placeholder": "Telephone Number"})

    level = SelectField('Level', choices=[('Admin', 'Admin'), ('Approver', 'Approver'), ('Requester', 'Requester'), ('Gate', 'Gate')])

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
    # visitors = Visitor.query.all()
    # visitor_ids = [visitor.visitorId for visitor in visitors]
    try:
        # Query to retrieve all values in the visitorNo column
        visitor_numbers = Visitor.query.with_entities(Visitor.visitorNo).all()

        # Dummy data - replace this with your actual data retrieval logic
        visitor_numbers_list = [1, 2, 3, 4, 5]

        # Convert the result to a list
        visitor_numbers_list = [number.visitorNo for number in visitor_numbers]

    except Exception as e:
        return jsonify({'error': str(e)})
    
    return render_template('dashboard.html', visitor_numbers=visitor_numbers_list) #, visitors=visitors, visitor_ids=visitor_ids

@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)

        # Check if the provided level is one of the allowed values
        allowed_levels = ['Admin', 'Approver', 'Requester', 'Gate']
        if form.level.data not in allowed_levels:
            flash('Invalid user level', 'error')
            return redirect(url_for('register'))

        new_user = User(
            username=form.username.data,
            password=hashed_password,
            email=form.email.data,
            level=form.level.data
        )

        with app.app_context():
            db.session.add(new_user)
            db.session.commit()
        flash('Account created successfully', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/arrive_visitor', methods=['POST'])
def arrive_visitor():
    visitor_no = request.form.get('visitor_no')
    visitor = Visitor.query.filter_by(visitorNo=visitor_no).first()

    if visitor:
        return render_template('arriveVisitor.html', visitor=visitor)
    else:
        return jsonify({'error': 'Visitofdyukfyukr not found'}), 404

# @app.route('/arrive_visitor', methods=['GET', 'POST'])
# def arrive_visitor():
#     visitor_no = request.form.get('visitor_no')
#     visitor = Visitor.query.filter_by(visitorNo=visitor_no).first()

#     if visitor:
#         return render_template('filledForm.html', visitor=visitor)
#     else:
#         return jsonify({'error': 'Visitor not found'}), 404
        
@app.route('/get_visitor', methods=['POST'])
def get_visitor():
    visitor_no = request.form.get('visitor_no')
    visitor = Visitor.query.filter_by(visitorNo=visitor_no).first()

    # change_status = 

    if visitor:
        return render_template('filledForm.html', visitor=visitor)
    else:
        return jsonify({'error': 'Visitor not found'}), 404
    
# @app.route('/filledForm', methods=['GET', 'POST'])
# def filledForm():
#     # Assuming you want the second record ordered by id
#     # getVisitor = 
#     global global_visitorNo
#     visitor_no_to_search = global_visitorNo
#     getVisitor = Visitor.query.filter_by(visitorNo=visitor_no_to_search).first()
#     if getVisitor:
#         lastName      = getVisitor.lastName
#         firstName     = getVisitor.firstName
#         companyName   = getVisitor.companyName
#         visitorId     = getVisitor.visitorId
#         arrivingDate  = getVisitor.arrivingDate
#         arrivingTime  = getVisitor.arrivingTime
#         departingDate = getVisitor.departingDate
#         departingTime = getVisitor.departingTime
#         vehicleNo     = getVisitor.vehicleNo
#         visitorNo     = getVisitor.visitorNo
#         phoneNumber   = getVisitor.phoneNumber
#         emailAddress  = getVisitor.emailAddress
#         requester     = getVisitor.requester
#         noOfVisitors  = getVisitor.noOfVisitors
#         remarks       = getVisitor.remarks
#         history       = getVisitor.history
#         status        = getVisitor.status
#     else:
#         lastName = ""

#     return render_template('filledForm.html',
#                            lastName=lastName,
#                            firstName=firstName,
#                            companyName=companyName,
#                            visitorId=visitorId,
#                            arrivingDate=arrivingDate,
#                            arrivingTime=arrivingTime,
#                            departingDate=departingDate,
#                            departingTime=departingTime,
#                            vehicleNo=vehicleNo,
#                            visitorNo=visitorNo,
#                            phoneNumber=phoneNumber,
#                            emailAddress=emailAddress,
#                            requester=requester,
#                            noOfVisitors=noOfVisitors,
#                            remarks=remarks,
#                            history=history,
#                            status=status)

if __name__ == "__main__":
    app.run(debug=True)

db.create_all()