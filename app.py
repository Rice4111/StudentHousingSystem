from flask import Flask, render_template, url_for, session, redirect, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum
from werkzeug.security import check_password_hash,generate_password_hash
from flask_migrate import Migrate
from datetime import datetime
from flask_mail import Message, Mail
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from flask import request as flask_request
import uuid
import os
from sqlalchemy.schema import CheckConstraint
from werkzeug.utils import secure_filename
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR,'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'swu4668@outlook.com'
app.config['MAIL_PASSWORD'] = 'testing+1s'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    #username = db.Column(db.String(150), unique=True, nullable=False)
    firstname = db.Column(db.String(150), nullable=False)
    lastname = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    user_type = db.Column(db.Enum('user', 'landlord', 'admin'), nullable=False, default='user')
    is_approved = db.Column(db.Boolean, default=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    requests = db.relationship('Request', backref='user', lazy=True)

    properties = db.relationship('Property', backref='owner', lazy=True)
    def set_password(self, password):
        self.password = generate_password_hash(password)

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, index=True)
    token = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

migrate = Migrate(app, db)

def send_reset_password_email(user, token):
    msg = Message('Reset Your Password', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
    msg.body = f'Click the link to reset your password: {url_for("reset_password", token=token, _external=True)}'
    mail.send(msg)

class Preference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rental_type = db.Column(db.String(50), nullable=False)
    pets_policy = db.Column(db.String(50), nullable=False)
    smoking_policy = db.Column(db.String(50), nullable=False)
    gender_policy = db.Column(db.String(50), nullable=False)
    sleep_policy = db.Column(db.String(50), nullable=False)
    term_policy = db.Column(db.String(50), nullable=False)
    additional_requirements = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<Preference {self.id} - Type: {self.rental_type}, Pets: {self.pets_policy}, Smoking: {self.smoking_policy}, Gender: {self.gender_policy}, Sleep: {self.sleep_policy}, Term: {self.term_policy}>"


class Preference_ll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rental_type = db.Column(db.String(50), nullable=False)
    pets_policy = db.Column(db.String(50), nullable=False)
    smoking_policy = db.Column(db.String(50), nullable=False)
    gender_policy = db.Column(db.String(50), nullable=False)
    sleep_policy = db.Column(db.String(50), nullable=False)
    term_policy = db.Column(db.String(50), nullable=False)
    additional_requirements = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    def __repr__(self):
        return f"<Preference {self.id} - Type: {self.rental_type}, Pets: {self.pets_policy}, Smoking: {self.smoking_policy}, Gender: {self.gender_policy}, Sleep: {self.sleep_policy}, Term: {self.term_policy}>"


class PaymentDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    card_number = db.Column(db.String(20), nullable=False)
    expiration_month = db.Column(db.String(2), nullable=False)
    expiration_year = db.Column(db.String(4), nullable=False)
    cvv = db.Column(db.String(4), nullable=False)

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_type = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=True)
    submitted_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return f'<Request {self.id}, Type: {self.request_type}>'
    
class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    availability = db.Column(db.Boolean, default=True, nullable=False)
    room_count = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(255), nullable=True, default='defaultH.png')
    detail = db.Column(db.Text, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


    __table_args__ = (CheckConstraint('room_count IN (1, 2, 3)'),)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/rent")
def rent():
    properties = Property.query.all()
    return render_template('rent.html',properties=properties)

@app.route("/user_dashboard")
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')
    
@app.route("/contact")
def contact():
    return render_template('contact.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.user_type == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.user_type == 'landlord':
            return redirect(url_for('landlord_dashboard'))
        else: 
            return redirect(url_for('user_dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Please enter something.', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            if not user.is_approved:
                flash('Your account is pending approval. Please contact admin.', 'warning')
                return redirect(url_for('login'))
            
            login_user(user)

            session['logged_in'] = True
            session['firstname'] = user.firstname
            session['user_type'] = user.user_type
            session['email'] = user.email
            session['image_file'] = user.image_file
            if user.user_type == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.user_type == 'landlord':
                return redirect(url_for('landlord_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
            
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route("/sign_up", methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        # username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        user_type = request.form.get('user_type')
        if not firstname or not lastname or not email or not password:
            flash('Please fill out all fields', 'danger')
            return render_template('sign_up.html')
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already in use', 'danger')
            return render_template('sign_up.html')
        
        new_user = User(
            firstname=firstname,
            lastname=lastname,
            email=email,
            password=generate_password_hash(password),
            user_type=user_type,
            is_approved=(user_type != 'landlord')

        )
        db.session.add(new_user)
        db.session.commit()

        if user_type == 'landlord':
            flash('Your account is under review. Please wait to be approved.', 'info')
            return redirect(url_for('login'))
        flash('Account created!', 'success')
        return redirect(url_for('login'))
    return render_template('sign_up.html')

@app.route('/logout')
def logout():
    # session.pop('logged_in', None)
    # session.pop('username', None)
    logout_user()
    return redirect(url_for('index'))

@app.route('/forget-password', methods=['GET', 'POST'])
def forget_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = uuid.uuid4().hex
            password_reset = PasswordReset(email=email, token=token)
            db.session.add(password_reset)
            db.session.commit()
            send_reset_password_email(user, token)
            flash('Check your email for the reset password link', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email address not found', 'danger')
    return render_template('forget_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    password_reset = PasswordReset.query.filter_by(token=token).first()
    if not password_reset:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        password = request.form.get('password')
        user = User.query.filter_by(email=password_reset.email).first()
        if user:
            user.set_password(password)
            db.session.commit()
            flash('Password updated successfully', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)


@app.route('/property_details/<int:property_id>')
@login_required
def property_details(property_id):
    property = Property.query.get_or_404(property_id)
    return render_template('property_details.html', property=property)


@app.route("/portfolio-details1")
def portfolio_details1():
    return render_template('portfolio-details1.html')
@app.route("/portfolio-details2")
def portfolio_details2():
    return render_template('portfolio-details2.html')
@app.route("/portfolio-details3")
def portfolio_details3():
    return render_template('portfolio-details3.html')

@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    user_count = User.query.count()
    return render_template('admin_dashboard.html', user_count=user_count)

@app.route("/landlord_dashboard")
@login_required
def landlord_dashboard():
    return render_template('landlord_dashboard.html')

@app.route("/contract")
@login_required
def contract():
    return render_template('contract.html')

@app.route("/database")
@login_required
def database():
    users = User.query.all()
    return render_template('database.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    firstname = request.form['firstname'].strip()
    lastname = request.form['lastname'].strip()
    email = request.form['email'].strip()

    if not firstname or not lastname or not email:
        flash('All fields are required.', 'danger')
        return redirect(url_for('your_view_function'))
    
    user.firstname = firstname
    user.lastname = lastname
    user.email = email
    db.session.commit()
    flash('User updated successfully.', 'success')
    return redirect(url_for('database'))
@app.route('/approve_user/<int:user_id>')
@login_required
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    db.session.commit()
    flash('User approved successfully.', 'success')
    return redirect(url_for('database'))

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('database'))


@app.route("/database_ll", methods=['GET', 'POST'])
@login_required
def database_ll():
    properties = Property.query.all()
    return render_template('database_ll.html', properties=properties)

@app.route('/add_property', methods=['POST'])
@login_required  # Ensure only logged-in users can add properties
def add_property():
    name = request.form['name']
    price = request.form['price']
    room_count = request.form['room_count']
    detail = request.form['detail']
    owner_id = current_user.id  # Assuming Flask-Login is used for user authentication

    image = request.files['image']
    image_url = 'defaultH.png'  # Default image
    if image and allowed_file(image.filename):
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        image_url = os.path.join('uploads', filename)

    new_property = Property(name=name, price=price, availability=True,
                            room_count=room_count, image_url=image_url,
                            detail=detail, owner_id=owner_id)
    db.session.add(new_property)
    db.session.commit()

    flash('Property added successfully!', 'success')
    return redirect(url_for('database_ll'))  # Redirect to the view where properties are listed

@app.route('/update_property/<int:property_id>', methods=['POST'])
@login_required
def update_property(property_id):
    property = Property.query.get_or_404(property_id)
    property.name = request.form['name']
    property.price = request.form['price']
    property.room_count = request.form['room_count']
    property.availability = request.form['availability'] == 'true'
    property.detail = request.form['detail']

    # Handle image upload if a new image has been uploaded
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            property.image_url = os.path.join('uploads', filename)

    db.session.commit()
    flash('Property updated successfully!', 'success')
    return redirect(url_for('database_ll'))


@app.route("/payment", methods=['GET', 'POST'])
@login_required
def payment():
    if request.method == 'POST':
        card_number = request.form.get('card_number')
        expiration_month = request.form.get('expiration_month')
        expiration_year = request.form.get('expiration_year')
        cvv = request.form.get('cvv')
        
        if not all([card_number, expiration_month, expiration_year, cvv]):
            flash('All payment fields are required', 'danger')
            return render_template('payment.html')

        if not card_number.isdigit() or len(card_number) not in [16, 19]:
            flash('Invalid card number', 'danger')
            return render_template('payment.html')

        from datetime import datetime
        current_year = datetime.now().year
        current_month = datetime.now().month
        if int(expiration_year) < current_year or (int(expiration_year) == current_year and int(expiration_month) < current_month):
            flash('Card has expired', 'danger')
            return render_template('payment.html')

        if not cvv.isdigit() or len(cvv) not in [3, 4]:
            flash('Invalid CVV', 'danger')
            return render_template('payment.html')

        existing_payment = PaymentDetails.query.filter_by(card_number=card_number).first()
        if existing_payment:
            flash('This card has already been used', 'warning')
            return render_template('payment.html')

        try:
            new_payment = PaymentDetails(
                card_number=card_number,
                expiration_month=expiration_month,
                expiration_year=expiration_year,
                cvv=cvv
            )
            db.session.add(new_payment)
            db.session.commit()
            flash('Payment processed successfully!', 'success')
            return redirect(url_for('paysuccess'))
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')
            db.session.rollback()
            return render_template('payment.html')

    return render_template('payment.html')


@app.route("/paysuccess")
@login_required
def paysuccess():
    return render_template('paysuccess.html')

@app.route('/preference', methods=['GET', 'POST'])
@login_required
def preference():
    existing_preference = Preference.query.filter_by(user_id=current_user.id).first()

    if request.method == 'POST':
        rental_type = request.form.get('RentalType')
        pets_policy = request.form.get('petsPolicy')
        smoking_policy = request.form.get('smokingPolicy')
        gender_policy = request.form.get('GenderPolicy')
        sleep_policy = request.form.get('SleepPolicy')
        term_policy = request.form.get('TermPolicy')
        additional_requirements = request.form.get('notice')

        if not rental_type or not pets_policy or not smoking_policy or not gender_policy or not sleep_policy or not term_policy:
            flash('Please fill out all fields', 'danger')
            return render_template('preference.html')
        
        existing_preference = Preference.query.filter_by(user_id=current_user.id).first()
        if existing_preference:
            existing_preference.rental_type = rental_type
            existing_preference.pets_policy = pets_policy
            existing_preference.smoking_policy = smoking_policy
            existing_preference.gender_policy = gender_policy
            existing_preference.sleep_policy = sleep_policy
            existing_preference.term_policy = term_policy
            existing_preference.additional_requirements = additional_requirements
        
        else:
            new_data = Preference(rental_type=rental_type, 
                                pets_policy=pets_policy, 
                                smoking_policy=smoking_policy, 
                                gender_policy=gender_policy, 
                                sleep_policy=sleep_policy, 
                                term_policy=term_policy,
                                additional_requirements=additional_requirements,
                                user_id=current_user.id
                                )
        
            db.session.add(new_data)

        db.session.commit()
        flash('Your preferences have been successfully submitted', 'success')
        return redirect(url_for('preference'))
    

    return render_template('preference.html', existing_preference=existing_preference)

@app.route('/preference_ll', methods=['GET', 'POST'])
@login_required
def preference_ll():
    existing_preference = Preference_ll.query.filter_by(user_id=current_user.id).first()

    if request.method == 'POST':
        rental_type = request.form.get('RentalType')
        pets_policy = request.form.get('petsPolicy')
        smoking_policy = request.form.get('smokingPolicy')
        gender_policy = request.form.get('GenderPolicy')
        sleep_policy = request.form.get('SleepPolicy')
        term_policy = request.form.get('TermPolicy')
        additional_requirements = request.form.get('notice')

        if not rental_type or not pets_policy or not smoking_policy or not gender_policy or not sleep_policy or not term_policy:
            flash('Please fill out all fields', 'danger')
            return render_template('preference.html')
        
        existing_preference = Preference_ll.query.filter_by(user_id=current_user.id).first()
        if existing_preference:
            existing_preference.rental_type = rental_type
            existing_preference.pets_policy = pets_policy
            existing_preference.smoking_policy = smoking_policy
            existing_preference.gender_policy = gender_policy
            existing_preference.sleep_policy = sleep_policy
            existing_preference.term_policy = term_policy
            existing_preference.additional_requirements = additional_requirements
        
        else:
            new_data = Preference_ll(rental_type=rental_type, 
                                pets_policy=pets_policy, 
                                smoking_policy=smoking_policy, 
                                gender_policy=gender_policy, 
                                sleep_policy=sleep_policy, 
                                term_policy=term_policy,
                                additional_requirements=additional_requirements,
                                user_id=current_user.id
                                )
        
            db.session.add(new_data)

        db.session.commit()
        flash('Your preferences have been successfully submitted', 'success')
        return redirect(url_for('preference_ll'))
    

    return render_template('preference_ll.html', existing_preference=existing_preference)


@app.route("/profile",  methods=['GET','POST'])
@login_required
def profile():
    if not session.get('logged_in'):
        flash('You need to log in to access this page.', 'warning')
        return redirect(url_for('login'))
    

    email = session.get('email')
    user = User.query.filter_by(email=email).first()

    if request.method == 'POST':

        new_firstname = request.form.get('firstname')
        
        if not new_firstname or len(new_firstname) < 1 or len(new_firstname) > 10:
            flash('Firstname must be between 1 and 10 characters.', 'danger')
        if user and new_firstname:
            user.firstname = new_firstname
            db.session.commit()
            session['firstname'] = new_firstname
            flash('Your firstname has been updated.', 'success')
        else:
            flash('There was an error updating your profile.', 'danger')
    
    return render_template('profile.html', user=user)
 
@app.route("/profile_ll",  methods=['GET','POST'])
@login_required
def profile_ll():
    if not session.get('logged_in'):
        flash('You need to log in to access this page.', 'warning')
        return redirect(url_for('login'))
    

    email = session.get('email')
    user = User.query.filter_by(email=email).first()

    if request.method == 'POST':

        new_firstname = request.form.get('firstname')
        
        if not new_firstname or len(new_firstname) < 1 or len(new_firstname) > 10:
            flash('Firstname must be between 1 and 10 characters.', 'danger')
        if user and new_firstname:
            user.firstname = new_firstname
            db.session.commit()
            session['firstname'] = new_firstname
            flash('Your firstname has been updated.', 'success')
        else:
            flash('There was an error updating your profile.', 'danger')
    return render_template('profile_ll.html')
@app.route("/rental")
@login_required
def rental():
    return render_template('rental.html')
@app.route("/request", methods=['GET', 'POST'])
@login_required
def requests():
    if request.method == 'POST':
        request_type = request.form.get('requestType')
        details = request.form.get('requestDetails')

        # Simple validation to ensure data is present
        if not request_type or not details:
            flash('Missing request type or details', 'danger')
            return redirect(url_for('requests'))  # Redirect back to the request form

        new_request = Request(request_type=request_type, details=details, user_id=current_user.id)
        db.session.add(new_request)
        db.session.commit()

        flash('Your request has been submitted successfully!', 'success')
        return redirect(url_for('requests')) 
    return render_template('request.html')
@app.route("/request_ll")
@login_required
def request_ll():
    requests = Request.query.all()
    return render_template('request_ll.html', requests=requests)
@app.route("/request_list")
@login_required
def request_list():
    requests = Request.query.all()
    return render_template('request_list.html', requests=requests)
@app.route("/result")
@login_required
def result():
    current_date = datetime.now().strftime("%B %d, %Y")
    return render_template('result.html', best_matches=None, current_date=current_date)

@app.route("/profile_admin")
@login_required
def profile_admin():
    return render_template('profile_admin.html')
@app.route("/request_admin")
@login_required
def request_admin():
    requests = Request.query.all()
    return render_template('request_admin.html', requests=requests)
@app.route('/submit_response/<int:request_id>', methods=['POST'])
@login_required
def submit_response(request_id):
    request_obj = Request.query.get_or_404(request_id)  # Renamed to request_obj to avoid naming conflict
    if request_obj.response:
        flash('Response already submitted.', 'warning')
    else:
        response_text = flask_request.form['response']  # Correctly accessing form data
        request_obj.response = response_text
        db.session.commit()
        flash('Response submitted successfully.', 'success')
    return redirect(url_for('request_admin'))
@app.route('/submit_response1/<int:request_id>', methods=['POST'])
@login_required
def submit_response1(request_id):
    request_obj = Request.query.get_or_404(request_id)  # Renamed to request_obj to avoid naming conflict
    if request_obj.response:
        flash('Response already submitted.', 'warning')
    else:
        response_text = flask_request.form['response']  # Correctly accessing form data
        request_obj.response = response_text
        db.session.commit()
        flash('Response submitted successfully.', 'success')
    return redirect(url_for('request_ll'))
@app.route('/delete_request/<int:request_id>')
@login_required
def delete_request(request_id):
    request = Request.query.get_or_404(request_id)
    db.session.delete(request)
    db.session.commit()
    flash('Request deleted successfully.', 'success')
    return redirect(url_for('request_admin'))

@app.route('/delete_property/<int:property_id>')
@login_required
def delete_property(property_id):
    property = Property.query.get_or_404(property_id) 
    db.session.delete(property)
    db.session.commit()
    flash('Property deleted successfully.', 'success')
    return redirect(url_for('database_ll'))

def calculate_match_score(property, user_preference, landlord_preference):
    score = 0
    
    rental_type_mapping = {
        'sole rental': 1,
        'shared rental': [2, 3]
    }
    
    expected_room_counts = rental_type_mapping.get(user_preference.rental_type)
    if isinstance(expected_room_counts, list):
        if property.room_count in expected_room_counts:
            score += 1
    else:
        if property.room_count == expected_room_counts:
            score += 1

    if user_preference.pets_policy == landlord_preference.pets_policy:
        score += 1
    if user_preference.smoking_policy == landlord_preference.smoking_policy:
        score += 1
    if user_preference.gender_policy == landlord_preference.gender_policy:
        score += 1
    if user_preference.sleep_policy == landlord_preference.sleep_policy:
        score += 1
    if user_preference.term_policy == landlord_preference.term_policy:
        score += 1


    return score




@app.route('/find_matches')
@login_required
def find_matches():
    user_preference = Preference.query.filter_by(user_id=current_user.id).first()
    all_properties = Property.query.filter_by(availability=True).all()
    best_matches = []
    current_date = datetime.now().strftime("%B %d, %Y")
    for property in all_properties:
        landlord_preference = Preference_ll.query.filter_by(user_id=property.owner_id).first()
        print(f"Landlord Preference for property {property.id}: {landlord_preference}")
        print(f"User Preference: {user_preference}")
        if landlord_preference:
            match_score = calculate_match_score(property, user_preference, landlord_preference)
            print(f"Match Score for property {property.id}: {match_score}")
            if match_score > 0:
                best_matches.append((match_score, property))



    best_matches.sort(key=lambda x: x[0], reverse=True)
    top_matches = [prop for _, prop in best_matches[:2]] 


    return render_template('result.html', best_matches=top_matches, current_date=current_date)



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 
