from flask import Flask, render_template, url_for, redirect, request, jsonify, flash, session, send_file, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, EmailField, SelectField, TelField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime
from base64 import b64encode
import openpyxl
from openpyxl.worksheet.table import Table, TableStyleInfo
from io import BytesIO
from werkzeug.utils import secure_filename
import os
from werkzeug.security import check_password_hash, generate_password_hash

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Add any other allowed file extensions

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

    def set_password(self, password):
        # Explicitly encode the password as bytes before hashing
        self.password = generate_password_hash(password.encode('utf-8'))

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Define the Visitor model
class Visitor(db.Model):
    id = db.Column(db.Integer)
    lastName = db.Column(db.String(50), nullable=False)
    firstName = db.Column(db.String(50), nullable=False)
    companyName = db.Column(db.String(100))
    visitorId = db.Column(db.String(15), nullable=False)
    arrivingDate = db.Column(db.String(20))
    arrivingTime = db.Column(db.String(20))
    departingDate = db.Column(db.String(20))
    departingTime = db.Column(db.String(20))
    vehicleNo = db.Column(db.String(20))
    visitorNo = db.Column(db.String(20), primary_key=True, nullable=False, autoincrement=False)
    phoneNumber = db.Column(db.String(20))
    emailAddress = db.Column(db.String(120))
    requester = db.Column(db.String(50))
    noOfVisitors = db.Column(db.Integer)
    remarks = db.Column(db.String(255))
    history = db.Column(db.String(255))
    status = db.Column(db.String(20))
    requestTime = db.Column(db.String(20))
    approver = db.Column(db.String(50))
    approvedTime = db.Column(db.String(20))
    arrivalOfficer = db.Column(db.String(50))
    arrivedTime = db.Column(db.String(20))
    departureOfficer = db.Column(db.String(50))
    departedTime = db.Column(db.String(20))
    profilePhoto = db.Column(db.String(255), nullable=True)
    committedDate = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)

class ImageUploadForm(FlaskForm):
    profilePhoto = FileField('Profile Photo', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Images only!')])
 
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route for the form
@app.route('/newvisitor', methods=['GET', 'POST'])
@login_required
def new_visitor():
    # visitor = Visitor.query.filter_by(visitorNo=visitor_id).first()

    visitor_code = generate_visitorCode()

    form = ImageUploadForm()

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
        
        if not visitor_id:
            # Render the template with an error message
            return render_template('newvisitor.html', 
                                   requester=current_user.username, 
                                   visitorNo=visitor_code,
                                   error_message='You must enter a Visitor ID')

        pic = request.files['pic']

        filename = secure_filename(pic.filename)
        
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
            profilePhoto=pic.read(),
            committedDate=datetime.utcnow()  # Assuming profilePhoto is the file path or name
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

class newPword(FlaskForm):
    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Save')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = newPword()
    if form.validate_on_submit():
        print("password accessed")
        user = current_user
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        
        user.password = hashed_password

        with app.app_context():
            db.session.commit()
        # if user:
        #     if bcrypt.check_password_hash(user.password, form.password.data):
        #         login_user(user)
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html', form=form)

@app.route('/get_user_by_username/<username>', methods=['GET'])
def get_user_by_username(username):
    user = User.query.filter_by(username=username).first()

    if user:
        return render_template('editUser.html', user=user)
    else:
        return "User not found", 404

@app.route('/update_user', methods=['POST'])
def update_user():
    if request.method == 'POST':
        # Get the form data
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        name = request.form.get('name')
        telephoneNo = request.form.get('telephoneNo')
        level = request.form.get('level')

        # Find the user by username
        user = User.query.filter_by(username=username).first()
        hashed_password = bcrypt.generate_password_hash(password)

        if user:
            # Update the user record
            user.password = hashed_password
            user.email = email
            user.name = name
            user.telephoneNo = telephoneNo
            user.level = level

            # Commit the changes to the database
            db.session.commit()

            # Redirect to a success page or any other appropriate action
            return redirect(url_for('all_users'))
        else:
            return "User not found", 404

    return "Invalid request", 400

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

@app.route('/', methods=['GET', 'POST'])
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
    try:
        # Query to retrieve visitorNos where the status is 'Pending'
        pending_visitor_numbers = Visitor.query.filter(Visitor.status == 'Pending', Visitor.requester != current_user.username).with_entities(Visitor.visitorNo).all()
        # Query to retrieve visitorNos where the status is 'Approved'
        approved_visitor_numbers = Visitor.query.filter_by(status='Approved').with_entities(Visitor.visitorNo).all()
        # Query to retrieve visitorNos where the status is 'Arrived'
        arrived_visitor_numbers = Visitor.query.filter_by(status='Arrived').with_entities(Visitor.visitorNo).all()

        # Convert the result to a list
        pending_visitor_numbers_list = [number.visitorNo for number in pending_visitor_numbers]
        approved_visitor_numbers_list = [number.visitorNo for number in approved_visitor_numbers]
        arrived_visitor_numbers_list = [number.visitorNo for number in arrived_visitor_numbers]

    except Exception as e:
        return jsonify({'error': str(e)})
    
    return render_template('dashboard.html',
                           pending_visitor_numbers=pending_visitor_numbers_list,
                           approved_visitor_numbers=approved_visitor_numbers_list,
                           arrived_visitor_numbers=arrived_visitor_numbers_list)

@ app.route('/register', methods=['GET', 'POST'])
@login_required
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
            name=form.name.data,
            telephoneNo=form.telephoneNo.data,
            level=form.level.data
        )

        with app.app_context():
            db.session.add(new_user)
            db.session.commit()
        flash('Account created successfully', 'success')
        return redirect(url_for('all_users'))

    return render_template('register.html', form=form)

@app.route('/arrive_visitor', methods=['POST'])
@login_required
def arrive_visitor():
    visitor_no = request.form.get('visitor_no')
    visitor = Visitor.query.filter_by(visitorNo=visitor_no).first()

    if visitor:
        # Access the value of the clicked button from the form data
        clicked_button_value = request.form.get('changeStatus')

        # Convert the BLOB data to Base64 encoding
        profile_photo_data = b64encode(visitor.profilePhoto).decode('utf-8')
           
        # Your logic based on the clicked button value
        if clicked_button_value == 'Arrived':
            visitor.status = 'Arrived'
            visitor.arrivalOfficer=current_user.username
            visitor.arrivedTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            visitor.remarks = request.form.get('remarks', '')
            db.session.commit()
            return redirect(url_for('dashboard'))

        return render_template('arriveVisitor.html', visitor=visitor, profile_photo_data=profile_photo_data)
    
    else:
        return jsonify({'error': 'Visitor not found', 'visitor_no': visitor_no}), 404

@app.route('/depart_visitor', methods=['POST'])
@login_required
def depart_visitor():
    visitor_no = request.form.get('visitor_no')
    visitor = Visitor.query.filter_by(visitorNo=visitor_no).first()

    if visitor:
        # Access the value of the clicked button from the form data
        clicked_button_value = request.form.get('changeStatus')

        # Convert the BLOB data to Base64 encoding
        profile_photo_data = b64encode(visitor.profilePhoto).decode('utf-8')
           
        # Your logic based on the clicked button value
        if clicked_button_value == 'Departed':
            visitor.status = 'Departed'
            visitor.departureOfficer=current_user.username
            visitor.departedTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            db.session.commit()
            return redirect(url_for('dashboard'))

        return render_template('departVisitor.html', visitor=visitor, profile_photo_data=profile_photo_data)
    
    else:
        return jsonify({'error': 'Visitor not found', 'visitor_no': visitor_no}), 404
        
@app.route('/get_visitor', methods=['POST'])
@login_required
def get_visitor():
    visitor_no = request.form.get('visitor_no')
    visitor = Visitor.query.filter_by(visitorNo=visitor_no).first()

    if visitor:
        # Access the value of the clicked button from the form data
        clicked_button_value = request.form.get('changeStatus')

        # Convert the BLOB data to Base64 encoding
        profile_photo_data = b64encode(visitor.profilePhoto).decode('utf-8')
           
        # Your logic based on the clicked button value
        if clicked_button_value == 'Approve':
            visitor.status = 'Approved'
            visitor.approver=current_user.username
            visitor.approvedTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            visitor.remarks = request.form.get('remarks', '')
            db.session.commit()
            return redirect(url_for('dashboard'))
        
        elif clicked_button_value == 'Reject':
            visitor.status = 'Rejected'
            visitor.approver=current_user.username
            visitor.approvedTime= datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            db.session.commit()
            return redirect(url_for('dashboard'))
         
        return render_template('filledForm.html', visitor=visitor, profile_photo_data=profile_photo_data)
    
    else:
        return jsonify({'error': 'Visitor not found', 'visitor_no': visitor_no}), 404

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

class DeleteUserForm(FlaskForm):
    submit = SubmitField('Delete Selected Users')

@app.route('/all_users', methods=['GET', 'POST'])
@login_required
def all_users():
    form = DeleteUserForm()

    if form.validate_on_submit():
        selected_ids = request.form.getlist('user_checkbox')
        User.query.filter(User.id.in_(selected_ids)).delete(synchronize_session=False)
        db.session.commit()

        return redirect(url_for('all_users', _anchor='reload'))

    search_query = request.form.get('search_query')
    users = get_filtered_users(search_query) if search_query else User.query.all()

    return render_template('allUsers.html', users=users, form=form)

def get_filtered_users(search_query):
    # Assuming you have a method to filter users based on a search query
    return User.query.filter(
        (User.username.like(f'%{search_query}%')) |
        (User.email.like(f'%{search_query}%')) |
        (User.name.like(f'%{search_query}%')) |
        (User.telephoneNo.like(f'%{search_query}%')) |
        (User.level.like(f'%{search_query}%'))
    ).all()

@app.route('/export_excel_user', methods=['POST'])
def export_excel_user():
    # Fetch data from the database
    data = User.query.all()

    # Create an Excel workbook and add a worksheet
    wb = openpyxl.Workbook()
    ws = wb.active

    # Define headers to be included in the worksheet
    headers = ['Index', 'username', 'email', 'name', 'telephoneNo', 'level']  # Include 'Index'
    ws.append(headers)

    # Write data to the worksheet with an index
    for index, row in enumerate(data, start=1):
        ws.append([index] + [getattr(row, field) for field in headers[1:]])

    # Create a table
    table = Table(displayName="UserData", ref=f"A1:{chr(ord('A') + len(headers) - 1)}{len(data) + 1}")
    style = TableStyleInfo(
        name="TableStyleMedium9", showFirstColumn=False,
        showLastColumn=False, showRowStripes=True, showColumnStripes=True)
    table.tableStyleInfo = style
    ws.add_table(table)

    # Adjust cell width to fit content
    for column in ws.columns:
        max_length = 0
        column = [cell for cell in column]
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(cell.value)
            except:
                pass
        adjusted_width = (max_length + 2)
        ws.column_dimensions[column[0].column_letter].width = adjusted_width

    # Save the workbook to BytesIO object
    excel_data = BytesIO()
    wb.save(excel_data)
    excel_data.seek(0)

    # Return the Excel file as a downloadable attachment
    return send_file(
        excel_data,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='users.xlsx'
    )

@app.route('/export_excel_visitor', methods=['POST'])
def export_excel_visitor():
    # Get start and end dates from the form
    start_date = request.form.get('startDate')
    end_date = request.form.get('endDate')

    # Convert start and end dates to datetime objects
    start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
    end_datetime = datetime.strptime(end_date, '%Y-%m-%d')

    # Fetch visitor data from the database based on the committed date range
    data = Visitor.query.filter(
        db.func.date(Visitor.committedDate) >= start_datetime.date(),
        db.func.date(Visitor.committedDate) <= end_datetime.date()
    ).all()

    # Create an Excel workbook and add a worksheet
    wb = openpyxl.Workbook()
    ws = wb.active

    # Define headers to be included in the worksheet (consistent with the User model)
    headers = [
        'id', 'visitorNo', 'visitorId', 'firstName', 'lastName', 'companyName', 'arrivingDate', 'arrivingTime',
        'departingDate', 'departingTime', 'vehicleNo', 'phoneNumber',
        'emailAddress', 'requester', 'noOfVisitors', 'remarks', 'history',
        'status', 'requestTime', 'approver', 'approvedTime', 'arrivalOfficer',
        'arrivedTime', 'departureOfficer', 'departedTime'
    ]

    # Write headers to the worksheet
    ws.append(headers)

    # Write data to the worksheet
    for row in data:
        ws.append([
            getattr(row, field) if field != 'committedDate' else row.committedDate.strftime('%Y-%m-%d %H:%M:%S')
            for field in headers
        ])

    # Create a table range
    table = Table(displayName="VisitorTable", ref=f"A1:{chr(ord('A') + len(headers) - 1)}{len(data) + 1}")

    # Add a TableStyleInfo to the table
    style = TableStyleInfo(
        name="TableStyleMedium9", showFirstColumn=False,
        showLastColumn=False, showRowStripes=True, showColumnStripes=True
    )
    table.tableStyleInfo = style

    # Add the table to the worksheet
    ws.add_table(table)

    # Adjust cell width to fit content
    for column in ws.columns:
        max_length = 0
        column = [cell for cell in column]
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(cell.value)
            except:
                pass
        adjusted_width = (max_length + 2)
        ws.column_dimensions[column[0].column_letter].width = adjusted_width

    # Save the workbook to BytesIO object
    excel_data = BytesIO()
    wb.save(excel_data)
    excel_data.seek(0)

    # Return the Excel file as a downloadable attachment
    return send_file(
        excel_data,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='visitor_records.xlsx'
    )


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    form = ImageUploadForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username='username_of_logged_in_user').first()  # Replace with actual username
        if user:
            image = form.image.data
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.root_path, 'static', 'uploads', filename))
            user.image = filename
            db.session.commit()
            return redirect(url_for('profile'))  # Redirect to user's profile page

    return render_template('error.html', form=form)

@app.route('/profile')
def profile():
    user = User.query.filter_by(username='username_of_logged_in_user').first()  # Replace with actual username
    return render_template('profile.html', user=user)

if __name__ == "__main__":
    app.run(debug=True)

db.create_all()