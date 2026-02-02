"""
Municipal Complaint Management System
Complete application in a single file
"""

import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ============= CONFIGURATION =============
app = Flask(__name__)
app.config['SECRET_KEY'] = 'municipal-compiler-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///municipal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Create uploads folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# ============= MODELS =============
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'user', 'officer', 'admin'
    taluka = db.Column(db.String(50), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(15), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_officer(self):
        return self.role == 'officer'
    
    def is_user(self):
        return self.role == 'user'

class Complaint(db.Model):
    __tablename__ = 'complaints'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    address = db.Column(db.String(300), nullable=True)
    image_path = db.Column(db.String(300), nullable=True)
    status = db.Column(db.String(20), default='pending')
    priority = db.Column(db.String(20), default='medium')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_officer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    taluka = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    # Resolution details
    resolved_image_path = db.Column(db.String(300), nullable=True)
    resolution_details = db.Column(db.Text, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Relationships
    author = db.relationship('User', foreign_keys=[user_id], backref='authored_complaints')
    assigned_officer = db.relationship('User', foreign_keys=[assigned_officer_id], backref='assigned_complaints')
    resolver = db.relationship('User', foreign_keys=[resolved_by], backref='resolved_complaints')

class RoadAnalysis(db.Model):
    __tablename__ = 'road_analysis'
    
    id = db.Column(db.Integer, primary_key=True)
    road_name = db.Column(db.String(200), nullable=False)
    taluka = db.Column(db.String(50), nullable=False)
    total_complaints = db.Column(db.Integer, default=0)
    pending_complaints = db.Column(db.Integer, default=0)
    resolved_complaints = db.Column(db.Integer, default=0)
    problem_score = db.Column(db.Float, default=0.0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ============= HELPER FUNCTIONS =============
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def role_required(role):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def update_road_analysis(address, taluka, resolved=False):
    if not address:
        return
    
    # Extract road name from address
    road_name = address.split(',')[0] if ',' in address else address
    
    road = RoadAnalysis.query.filter_by(road_name=road_name, taluka=taluka).first()
    
    if not road:
        road = RoadAnalysis(road_name=road_name, taluka=taluka)
        db.session.add(road)
    
    # Initialize values
    road.total_complaints = road.total_complaints or 0
    road.pending_complaints = road.pending_complaints or 0
    road.resolved_complaints = road.resolved_complaints or 0
    road.problem_score = road.problem_score or 0.0
    
    if resolved:
        road.resolved_complaints += 1
        road.pending_complaints = max(0, road.pending_complaints - 1)
    else:
        road.total_complaints += 1
        road.pending_complaints += 1
    
    # Calculate problem score
    if road.resolved_complaints > 0:
        road.problem_score = (road.pending_complaints * 0.7 + road.total_complaints * 0.3) / road.resolved_complaints
    else:
        road.problem_score = road.pending_complaints * 0.7 + road.total_complaints * 0.3
    
    road.last_updated = datetime.utcnow()
    db.session.commit()

# ============= FLASK-LOGIN CONFIG =============
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ============= ROUTES =============
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role', 'user')
    taluka = request.form.get('taluka', '')
    phone = request.form.get('phone', '')
    department = request.form.get('department', '')
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'danger')
        return redirect(url_for('login'))
    
    if User.query.filter_by(email=email).first():
        flash('Email already registered', 'danger')
        return redirect(url_for('login'))
    
    user = User(
        username=username,
        email=email,
        role=role,
        taluka=taluka,
        phone=phone,
        department=department if role == 'officer' else None
    )
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    flash('Registration successful! Please login.', 'success')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'officer':
        return redirect(url_for('officer_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))

@app.route('/user/dashboard')
@login_required
@role_required('user')
def user_dashboard():
    user_complaints = Complaint.query.filter_by(user_id=current_user.id).order_by(Complaint.created_at.desc()).all()
    return render_template('user_dashboard.html', complaints=user_complaints)

@app.route('/officer/dashboard')
@login_required
@role_required('officer')
def officer_dashboard():
    assigned_complaints = Complaint.query.filter_by(assigned_officer_id=current_user.id).order_by(Complaint.created_at.desc()).all()
    taluka_complaints = Complaint.query.filter_by(taluka=current_user.taluka, status='pending').all() if current_user.taluka else []
    return render_template('officer_dashboard.html', 
                         assigned_complaints=assigned_complaints,
                         taluka_complaints=taluka_complaints)

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    roads = RoadAnalysis.query.order_by(RoadAnalysis.problem_score.desc()).limit(10).all()
    stats = {
        'total_complaints': Complaint.query.count() or 0,
        'pending_complaints': Complaint.query.filter_by(status='pending').count() or 0,
        'resolved_complaints': Complaint.query.filter_by(status='resolved').count() or 0,
        'total_users': User.query.count() or 0
    }
    recent_complaints = Complaint.query.order_by(Complaint.created_at.desc()).limit(10).all()
    return render_template('admin_dashboard.html', roads=roads, stats=stats, recent_complaints=recent_complaints)

@app.route('/complaint/new', methods=['GET', 'POST'])
@login_required
def new_complaint():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        address = request.form.get('address')
        
        # Handle file upload
        image_file = request.files.get('image')
        image_filename = None
        
        if image_file and allowed_file(image_file.filename):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            original_filename = secure_filename(image_file.filename)
            image_filename = f"{timestamp}_{original_filename}"
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image_file.save(image_path)
        
        taluka = current_user.taluka or 'General'
        
        complaint = Complaint(
            title=title,
            description=description,
            category=category,
            latitude=float(latitude) if latitude else None,
            longitude=float(longitude) if longitude else None,
            address=address,
            image_path=image_filename,
            user_id=current_user.id,
            taluka=taluka
        )
        
        db.session.add(complaint)
        db.session.commit()
        
        update_road_analysis(address, taluka)
        flash('Complaint submitted successfully!', 'success')
        return redirect(url_for('user_dashboard'))
    
    return render_template('new_complaint.html')

@app.route('/complaint/resolve/<int:complaint_id>', methods=['POST'])
@login_required
@role_required('officer')
def resolve_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    
    resolution_details = request.form.get('resolution_details')
    resolved_image = request.files.get('resolved_image')
    
    resolved_image_filename = None
    if resolved_image and allowed_file(resolved_image.filename):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        original_filename = secure_filename(resolved_image.filename)
        resolved_image_filename = f"resolved_{timestamp}_{original_filename}"
        resolved_image_path = os.path.join(app.config['UPLOAD_FOLDER'], resolved_image_filename)
        resolved_image.save(resolved_image_path)
        complaint.resolved_image_path = resolved_image_filename
    
    complaint.status = 'resolved'
    complaint.resolution_details = resolution_details
    complaint.resolved_at = datetime.utcnow()
    complaint.resolved_by = current_user.id
    
    db.session.commit()
    update_road_analysis(complaint.address, complaint.taluka, resolved=True)
    flash('Complaint marked as resolved!', 'success')
    return redirect(url_for('officer_dashboard'))

@app.route('/complaint/assign/<int:complaint_id>/<int:officer_id>')
@login_required
@role_required('admin')
def assign_complaint(complaint_id, officer_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    officer = User.query.get_or_404(officer_id)
    
    complaint.assigned_officer_id = officer_id
    complaint.status = 'in_progress'
    db.session.commit()
    
    flash(f'Complaint assigned to {officer.username}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/api/officers')
@login_required
def get_officers():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    officers = User.query.filter_by(role='officer').all()
    data = [{
        'id': officer.id,
        'username': officer.username,
        'taluka': officer.taluka or 'Not specified',
        'department': officer.department or 'Not specified'
    } for officer in officers]
    
    return jsonify(data)

@app.route('/api/roads/analysis')
@login_required
def get_road_analysis():
    roads = RoadAnalysis.query.order_by(RoadAnalysis.problem_score.desc()).all()
    data = [{
        'road_name': road.road_name,
        'taluka': road.taluka,
        'total': road.total_complaints or 0,
        'pending': road.pending_complaints or 0,
        'score': road.problem_score or 0
    } for road in roads]
    
    return jsonify(data)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/complaints/stats')
@login_required
def get_complaint_stats():
    if current_user.role == 'user':
        total = Complaint.query.filter_by(user_id=current_user.id).count()
        resolved = Complaint.query.filter_by(user_id=current_user.id, status='resolved').count()
        pending = Complaint.query.filter_by(user_id=current_user.id, status='pending').count()
    elif current_user.role == 'officer':
        total = Complaint.query.filter_by(taluka=current_user.taluka).count() if current_user.taluka else 0
        resolved = Complaint.query.filter_by(taluka=current_user.taluka, status='resolved').count() if current_user.taluka else 0
        pending = Complaint.query.filter_by(taluka=current_user.taluka, status='pending').count() if current_user.taluka else 0
    else:
        total = Complaint.query.count()
        resolved = Complaint.query.filter_by(status='resolved').count()
        pending = Complaint.query.filter_by(status='pending').count()
    
    return jsonify({
        'total': total,
        'resolved': resolved,
        'pending': pending,
        'resolution_rate': (resolved / total * 100) if total > 0 else 0
    })

@app.route('/complaints')
@login_required
def view_complaints():
    if current_user.role == 'admin':
        complaints = Complaint.query.order_by(Complaint.created_at.desc()).all()
    elif current_user.role == 'officer':
        complaints = Complaint.query.filter_by(taluka=current_user.taluka).order_by(Complaint.created_at.desc()).all() if current_user.taluka else []
    else:
        complaints = Complaint.query.filter_by(user_id=current_user.id).order_by(Complaint.created_at.desc()).all()
    
    return render_template('view_complaints.html', complaints=complaints)

# ============= TEMPLATES (Inline HTML) =============
@app.route('/templates/<template_name>')
def serve_template(template_name):
    templates = {
        'base.html': BASE_TEMPLATE,
        'login.html': LOGIN_TEMPLATE,
        'user_dashboard.html': USER_DASHBOARD_TEMPLATE,
        'officer_dashboard.html': OFFICER_DASHBOARD_TEMPLATE,
        'admin_dashboard.html': ADMIN_DASHBOARD_TEMPLATE,
        'new_complaint.html': NEW_COMPLAINT_TEMPLATE,
        'view_complaints.html': VIEW_COMPLAINTS_TEMPLATE
    }
    
    if template_name in templates:
        return templates[template_name]
    return 'Template not found', 404

# But for actual rendering, we'll use Flask's template system
# We need to create template files. Let me create a simple setup function:

def create_template_files():
    """Create template files if they don't exist"""
    template_dir = 'templates'
    os.makedirs(template_dir, exist_ok=True)
    
    templates = {
        'base.html': BASE_TEMPLATE,
        'login.html': LOGIN_TEMPLATE,
        'user_dashboard.html': USER_DASHBOARD_TEMPLATE,
        'officer_dashboard.html': OFFICER_DASHBOARD_TEMPLATE,
        'admin_dashboard.html': ADMIN_DASHBOARD_TEMPLATE,
        'new_complaint.html': NEW_COMPLAINT_TEMPLATE,
        'view_complaints.html': VIEW_COMPLAINTS_TEMPLATE
    }
    
    for filename, content in templates.items():
        filepath = os.path.join(template_dir, filename)
        if not os.path.exists(filepath):
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Created template: {filename}")

# ============= TEMPLATE CONTENT =============

BASE_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Municipal Compiler{% endblock %}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #1a5f7a;
            --secondary-color: #57cc99;
            --accent-color: #ff9a3c;
            --danger-color: #ff6b6b;
            --warning-color: #ffd93d;
            --success-color: #6bcf7f;
            --light-color: #f8f9fa;
            --dark-color: #343a40;
            --gray-color: #6c757d;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            min-height: 100vh;
        }
        
        .header {
            background: linear-gradient(135deg, #1a5f7a 0%, #2286c3 100%);
            color: white;
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo { display: flex; align-items: center; gap: 15px; }
        .logo-icon { 
            width: 50px; height: 50px; 
            background: white; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            color: var(--primary-color); font-size: 24px;
        }
        
        .nav { display: flex; gap: 20px; }
        .nav a { color: white; text-decoration: none; padding: 8px 16px; }
        .nav a:hover { background: rgba(255,255,255,0.2); border-radius: 5px; }
        
        .container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }
        
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background: var(--primary-color);
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
        }
        
        .btn:hover { opacity: 0.9; }
        
        .form-group { margin-bottom: 15px; }
        .form-control {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        
        .alert {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .alert-success { background: #d4edda; color: #155724; }
        .alert-danger { background: #f8d7da; color: #721c24; }
        .alert-info { background: #d1ecf1; color: #0c5460; }
        
        .complaint-item {
            background: white;
            border-left: 5px solid var(--primary-color);
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
        }
        
        .status { padding: 5px 10px; border-radius: 15px; font-size: 0.9em; }
        .status-pending { background: #fff3cd; color: #856404; }
        .status-resolved { background: #d4edda; color: #155724; }
        .status-in_progress { background: #cce5ff; color: #004085; }
        
        .footer {
            background: var(--dark-color);
            color: white;
            text-align: center;
            padding: 20px;
            margin-top: 40px;
        }
        
        @media (max-width: 768px) {
            .header { flex-direction: column; gap: 15px; }
            .nav { flex-wrap: wrap; justify-content: center; }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="logo">
            <div class="logo-icon">
                <i class="fas fa-city"></i>
            </div>
            <div>
                <h1>Municipal Compiler</h1>
                <p>Smart Complaint Management</p>
            </div>
        </div>
        
        <nav class="nav">
            {% if current_user.is_authenticated %}
                <a href="{{ url_for('dashboard') }}"><i class="fas fa-home"></i> Dashboard</a>
                {% if current_user.role == 'user' %}
                    <a href="{{ url_for('new_complaint') }}"><i class="fas fa-plus"></i> New Complaint</a>
                {% endif %}
                <a href="{{ url_for('view_complaints') }}"><i class="fas fa-list"></i> Complaints</a>
                <a href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt"></i> Logout</a>
                <span style="padding: 8px 16px;">
                    <i class="fas fa-user"></i> {{ current_user.username }} ({{ current_user.role }})
                </span>
            {% endif %}
        </nav>
    </header>
    
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
    
    <footer class="footer">
        <p>&copy; 2024 Municipal Corporation. All rights reserved.</p>
        <p>Emergency: 100 (Police) | 101 (Fire) | 108 (Ambulance)</p>
    </footer>
    
    <script>
        // Simple JavaScript for image preview
        function previewImage(input) {
            if (input.files && input.files[0]) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    const preview = document.getElementById('imagePreview');
                    if (preview) {
                        preview.src = e.target.result;
                        preview.style.display = 'block';
                    }
                }
                reader.readAsDataURL(input.files[0]);
            }
        }
        
        // Get location
        function getLocation() {
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(
                    function(position) {
                        document.getElementById('latitude').value = position.coords.latitude;
                        document.getElementById('longitude').value = position.coords.longitude;
                        alert('Location captured successfully!');
                    },
                    function() {
                        alert('Unable to get location. Please enter manually.');
                    }
                );
            } else {
                alert('Geolocation not supported.');
            }
        }
    </script>
</body>
</html>'''

LOGIN_TEMPLATE = '''{% extends "base.html" %}

{% block title %}Login - Municipal Compiler{% endblock %}

{% block content %}
<div class="card" style="max-width: 500px; margin: 50px auto;">
    <h2 style="text-align: center; margin-bottom: 20px;">
        <i class="fas fa-city"></i> Municipal Compiler
    </h2>
    
    <form method="POST" action="{{ url_for('login') }}">
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" class="form-control" required>
        </div>
        
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" class="form-control" required>
        </div>
        
        <button type="submit" class="btn" style="width: 100%;">
            <i class="fas fa-sign-in-alt"></i> Login
        </button>
    </form>
    
    <hr style="margin: 20px 0;">
    
    <h3 style="text-align: center;">Register New Account</h3>
    
    <form method="POST" action="{{ url_for('register') }}">
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" class="form-control" required>
        </div>
        
        <div class="form-group">
            <label>Email</label>
            <input type="email" name="email" class="form-control" required>
        </div>
        
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" class="form-control" required>
        </div>
        
        <div class="form-group">
            <label>Phone Number</label>
            <input type="tel" name="phone" class="form-control">
        </div>
        
        <div class="form-group">
            <label>Taluka</label>
            <select name="taluka" class="form-control" required>
                <option value="">Select Taluka</option>
                <option value="Central">Central</option>
                <option value="North">North</option>
                <option value="South">South</option>
                <option value="East">East</option>
                <option value="West">West</option>
            </select>
        </div>
        
        <div class="form-group">
            <label>Role</label>
            <select name="role" class="form-control" required>
                <option value="user">Citizen</option>
                <option value="officer">Government Officer</option>
                <option value="admin">Administrator</option>
            </select>
        </div>
        
        <div id="departmentField" style="display: none;">
            <div class="form-group">
                <label>Department (for officers)</label>
                <input type="text" name="department" class="form-control">
            </div>
        </div>
        
        <button type="submit" class="btn" style="width: 100%; background: var(--secondary-color);">
            <i class="fas fa-user-plus"></i> Register
        </button>
    </form>
</div>

<script>
    document.querySelector('select[name="role"]').addEventListener('change', function() {
        const deptField = document.getElementById('departmentField');
        deptField.style.display = this.value === 'officer' ? 'block' : 'none';
    });
</script>
{% endblock %}'''

USER_DASHBOARD_TEMPLATE = '''{% extends "base.html" %}

{% block title %}User Dashboard{% endblock %}

{% block content %}
<h1><i class="fas fa-user"></i> Welcome, {{ current_user.username }}</h1>
<p>Citizen Dashboard - Track your complaints</p>

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0;">
    <div class="card">
        <h3><i class="fas fa-file-alt"></i> Total Complaints</h3>
        <p style="font-size: 2em; color: var(--primary-color);" id="totalCount">0</p>
    </div>
    
    <div class="card">
        <h3><i class="fas fa-clock"></i> Pending</h3>
        <p style="font-size: 2em; color: var(--warning-color);" id="pendingCount">0</p>
    </div>
    
    <div class="card">
        <h3><i class="fas fa-check-circle"></i> Resolved</h3>
        <p style="font-size: 2em; color: var(--success-color);" id="resolvedCount">0</p>
    </div>
</div>

<div style="text-align: center; margin: 30px 0;">
    <a href="{{ url_for('new_complaint') }}" class="btn" style="font-size: 1.2em;">
        <i class="fas fa-plus-circle"></i> File New Complaint
    </a>
</div>

<h2>Your Recent Complaints</h2>

{% if complaints %}
    {% for complaint in complaints %}
    <div class="complaint-item">
        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
            <h3>{{ complaint.title }}</h3>
            <span class="status status-{{ complaint.status }}">
                {{ complaint.status|replace('_', ' ')|title }}
            </span>
        </div>
        
        <p>{{ complaint.description }}</p>
        
        {% if complaint.image_path %}
        <div style="margin: 10px 0;">
            <img src="{{ url_for('uploaded_file', filename=complaint.image_path) }}" 
                 alt="Complaint Image" style="max-width: 300px; border-radius: 5px;">
        </div>
        {% endif %}
        
        <div style="margin-top: 10px; color: var(--gray-color); font-size: 0.9em;">
            <i class="fas fa-calendar"></i> {{ complaint.created_at.strftime('%d %b %Y') }} |
            <i class="fas fa-map-marker-alt"></i> {{ complaint.taluka }} |
            <i class="fas fa-tag"></i> {{ complaint.category }}
        </div>
        
        {% if complaint.status == 'resolved' and complaint.resolution_details %}
        <div style="background: #d4edda; padding: 10px; border-radius: 5px; margin-top: 10px;">
            <h4><i class="fas fa-check-circle"></i> Resolution</h4>
            <p>{{ complaint.resolution_details }}</p>
            {% if complaint.resolved_image_path %}
            <img src="{{ url_for('uploaded_file', filename=complaint.resolved_image_path) }}" 
                 alt="Resolution Image" style="max-width: 200px; border-radius: 5px; margin-top: 10px;">
            {% endif %}
        </div>
        {% endif %}
    </div>
    {% endfor %}
{% else %}
<div class="card" style="text-align: center; padding: 40px;">
    <i class="fas fa-inbox fa-3x" style="color: var(--gray-color); margin-bottom: 20px;"></i>
    <h3>No Complaints Yet</h3>
    <p>You haven't filed any complaints yet.</p>
    <a href="{{ url_for('new_complaint') }}" class="btn" style="margin-top: 20px;">
        <i class="fas fa-plus-circle"></i> File Your First Complaint
    </a>
</div>
{% endif %}

<script>
    // Load stats
    fetch('/api/complaints/stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('totalCount').textContent = data.total;
            document.getElementById('pendingCount').textContent = data.pending;
            document.getElementById('resolvedCount').textContent = data.resolved;
        });
</script>
{% endblock %}'''

OFFICER_DASHBOARD_TEMPLATE = '''{% extends "base.html" %}

{% block title %}Officer Dashboard{% endblock %}

{% block content %}
<h1><i class="fas fa-user-tie"></i> Officer Dashboard</h1>
<p>Welcome, Officer {{ current_user.username }}</p>

<h2>Complaints Assigned to You</h2>

{% if assigned_complaints %}
    {% for complaint in assigned_complaints %}
    <div class="complaint-item">
        <div style="display: flex; justify-content: space-between;">
            <div>
                <h3>{{ complaint.title }}</h3>
                <p style="color: var(--gray-color);">
                    <i class="fas fa-user"></i> {{ complaint.author.username }} |
                    <i class="fas fa-map-marker-alt"></i> {{ complaint.address or 'N/A' }}
                </p>
            </div>
            <span class="status status-{{ complaint.status }}">
                {{ complaint.status|replace('_', ' ')|title }}
            </span>
        </div>
        
        <p>{{ complaint.description }}</p>
        
        {% if complaint.image_path %}
        <div style="margin: 10px 0;">
            <img src="{{ url_for('uploaded_file', filename=complaint.image_path) }}" 
                 alt="Complaint Image" style="max-width: 300px; border-radius: 5px;">
        </div>
        {% endif %}
        
        {% if complaint.status != 'resolved' %}
        <form method="POST" action="{{ url_for('resolve_complaint', complaint_id=complaint.id) }}" 
              enctype="multipart/form-data" style="margin-top: 15px;">
            <div class="form-group">
                <label>Resolution Details</label>
                <textarea name="resolution_details" class="form-control" rows="3" required></textarea>
            </div>
            
            <div class="form-group">
                <label>Upload Resolution Photo (Optional)</label>
                <input type="file" name="resolved_image" class="form-control" accept="image/*">
            </div>
            
            <button type="submit" class="btn" style="background: var(--success-color);">
                <i class="fas fa-check"></i> Mark as Resolved
            </button>
        </form>
        {% else %}
        <div style="background: #d4edda; padding: 10px; border-radius: 5px; margin-top: 10px;">
            <h4><i class="fas fa-check-circle"></i> Already Resolved</h4>
            <p>{{ complaint.resolution_details }}</p>
        </div>
        {% endif %}
    </div>
    {% endfor %}
{% else %}
<div class="card" style="text-align: center; padding: 40px;">
    <i class="fas fa-inbox fa-3x" style="color: var(--gray-color); margin-bottom: 20px;"></i>
    <h3>No Assigned Complaints</h3>
    <p>You don't have any complaints assigned to you.</p>
</div>
{% endif %}

{% if taluka_complaints %}
<h2>Pending Complaints in {{ current_user.taluka }}</h2>
{% for complaint in taluka_complaints %}
<div class="complaint-item">
    <h3>{{ complaint.title }}</h3>
    <p>{{ complaint.description[:200] }}...</p>
    <p style="color: var(--gray-color); font-size: 0.9em;">
        <i class="fas fa-user"></i> {{ complaint.author.username }} |
        <i class="fas fa-calendar"></i> {{ complaint.created_at.strftime('%d %b %Y') }}
    </p>
</div>
{% endfor %}
{% endif %}
{% endblock %}'''

ADMIN_DASHBOARD_TEMPLATE = '''{% extends "base.html" %}

{% block title %}Admin Dashboard{% endblock %}

{% block content %}
<h1><i class="fas fa-user-shield"></i> Admin Dashboard</h1>
<p>System Management Console</p>

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0;">
    <div class="card">
        <h3><i class="fas fa-file-alt"></i> Total Complaints</h3>
        <p style="font-size: 2em; color: var(--primary-color);">{{ stats.total_complaints }}</p>
    </div>
    
    <div class="card">
        <h3><i class="fas fa-clock"></i> Pending</h3>
        <p style="font-size: 2em; color: var(--warning-color);">{{ stats.pending_complaints }}</p>
    </div>
    
    <div class="card">
        <h3><i class="fas fa-check-circle"></i> Resolved</h3>
        <p style="font-size: 2em; color: var(--success-color);">{{ stats.resolved_complaints }}</p>
    </div>
    
    <div class="card">
        <h3><i class="fas fa-users"></i> Total Users</h3>
        <p style="font-size: 2em; color: var(--secondary-color);">{{ stats.total_users }}</p>
    </div>
</div>

<h2><i class="fas fa-road"></i> Road Analysis (Top Problematic Roads)</h2>
{% if roads %}
    {% for road in roads %}
    <div class="card" style="margin-bottom: 10px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h3>{{ road.road_name }}</h3>
                <p style="color: var(--gray-color);">
                    <i class="fas fa-map-marker-alt"></i> {{ road.taluka }} |
                    Total: {{ road.total_complaints or 0 }} |
                    Pending: {{ road.pending_complaints or 0 }}
                </p>
            </div>
            <div>
                <div style="width: 100px; height: 10px; background: #e9ecef; border-radius: 5px; overflow: hidden;">
                    <div style="width: {{ (road.problem_score or 0) * 10 }}%; height: 100%; background: var(--danger-color);"></div>
                </div>
                <p style="text-align: center; margin-top: 5px; font-weight: bold;">
                    Score: {{ "%.1f"|format(road.problem_score or 0) }}
                </p>
            </div>
        </div>
    </div>
    {% endfor %}
{% else %}
<div class="card">
    <p>No road analysis data available.</p>
</div>
{% endif %}

<h2>Recent Complaints</h2>
{% if recent_complaints %}
    {% for complaint in recent_complaints %}
    <div class="complaint-item">
        <div style="display: flex; justify-content: space-between;">
            <div>
                <h3>{{ complaint.title }}</h3>
                <p style="color: var(--gray-color);">
                    <i class="fas fa-user"></i> {{ complaint.author.username }} |
                    <i class="fas fa-map-marker-alt"></i> {{ complaint.taluka }}
                </p>
            </div>
            <span class="status status-{{ complaint.status }}">
                {{ complaint.status|replace('_', ' ')|title }}
            </span>
        </div>
        
        <p>{{ complaint.description[:150] }}...</p>
        
        <div style="margin-top: 10px;">
            {% if complaint.status == 'pending' %}
            <button onclick="assignComplaint({{ complaint.id }})" class="btn btn-sm">
                <i class="fas fa-user-tie"></i> Assign Officer
            </button>
            {% endif %}
            
            {% if complaint.image_path %}
            <a href="{{ url_for('uploaded_file', filename=complaint.image_path) }}" 
               target="_blank" class="btn btn-sm" style="background: var(--secondary-color);">
                <i class="fas fa-eye"></i> View Image
            </a>
            {% endif %}
        </div>
    </div>
    {% endfor %}
{% else %}
<div class="card">
    <p>No recent complaints.</p>
</div>
{% endif %}

<script>
function assignComplaint(complaintId) {
    fetch('/api/officers')
        .then(response => response.json())
        .then(officers => {
            let options = officers.map(o => 
                `<option value="${o.id}">${o.username} (${o.taluka})</option>`
            ).join('');
            
            const officerId = prompt(`Select officer ID to assign complaint ${complaintId}:\n\nAvailable officers:\n${officers.map(o => `${o.id}: ${o.username}`).join('\\n')}`);
            
            if (officerId) {
                window.location.href = `/complaint/assign/${complaintId}/${officerId}`;
            }
        });
}
</script>
{% endblock %}'''

NEW_COMPLAINT_TEMPLATE = '''{% extends "base.html" %}

{% block title %}File New Complaint{% endblock %}

{% block content %}
<h1><i class="fas fa-plus-circle"></i> File New Complaint</h1>

<form method="POST" action="{{ url_for('new_complaint') }}" enctype="multipart/form-data" class="card">
    <div class="form-group">
        <label>Complaint Title*</label>
        <input type="text" name="title" class="form-control" required placeholder="e.g., Pothole on Main Road">
    </div>
    
    <div class="form-group">
        <label>Category*</label>
        <select name="category" class="form-control" required>
            <option value="">Select Category</option>
            <option value="Road">Road & Infrastructure</option>
            <option value="Water">Water Supply</option>
            <option value="Electricity">Electricity</option>
            <option value="Sanitation">Sanitation & Garbage</option>
            <option value="Other">Other Issues</option>
        </select>
    </div>
    
    <div class="form-group">
        <label>Description*</label>
        <textarea name="description" class="form-control" rows="5" required 
                  placeholder="Describe the issue in detail..."></textarea>
    </div>
    
    <div class="form-group">
        <label>Upload Photo (Optional)</label>
        <input type="file" name="image" class="form-control" accept="image/*" onchange="previewImage(this)">
        
        <div id="imagePreviewContainer" style="margin-top: 10px; display: none;">
            <img id="imagePreview" style="max-width: 300px; border-radius: 5px;">
        </div>
    </div>
    
    <div class="form-group">
        <label>Location</label>
        <button type="button" class="btn" onclick="getLocation()" style="margin-bottom: 10px;">
            <i class="fas fa-location-arrow"></i> Get Current Location
        </button>
        
        <input type="hidden" id="latitude" name="latitude">
        <input type="hidden" id="longitude" name="longitude">
        
        <input type="text" name="address" class="form-control" placeholder="Enter address or landmark">
    </div>
    
    <div style="margin-top: 20px;">
        <button type="submit" class="btn" style="font-size: 1.1em;">
            <i class="fas fa-paper-plane"></i> Submit Complaint
        </button>
        <a href="{{ url_for('user_dashboard') }}" class="btn" style="background: var(--gray-color);">
            Cancel
        </a>
    </div>
</form>

<script>
function previewImage(input) {
    const container = document.getElementById('imagePreviewContainer');
    const preview = document.getElementById('imagePreview');
    
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            preview.src = e.target.result;
            container.style.display = 'block';
        }
        reader.readAsDataURL(input.files[0]);
    } else {
        container.style.display = 'none';
    }
}
</script>
{% endblock %}'''

VIEW_COMPLAINTS_TEMPLATE = '''{% extends "base.html" %}

{% block title %}All Complaints{% endblock %}

{% block content %}
<h1><i class="fas fa-list"></i> All Complaints</h1>
<p>Viewing all complaints in the system</p>

{% if complaints %}
    {% for complaint in complaints %}
    <div class="complaint-item">
        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
            <div>
                <h3>{{ complaint.title }}</h3>
                <p style="color: var(--gray-color);">
                    <i class="fas fa-user"></i> {{ complaint.author.username }} |
                    <i class="fas fa-map-marker-alt"></i> {{ complaint.taluka }} |
                    <i class="fas fa-calendar"></i> {{ complaint.created_at.strftime('%d %b %Y') }}
                </p>
            </div>
            <span class="status status-{{ complaint.status }}">
                {{ complaint.status|replace('_', ' ')|title }}
            </span>
        </div>
        
        <p>{{ complaint.description }}</p>
        
        {% if complaint.image_path %}
        <div style="margin: 10px 0;">
            <img src="{{ url_for('uploaded_file', filename=complaint.image_path) }}" 
                 alt="Complaint Image" style="max-width: 300px; border-radius: 5px;">
        </div>
        {% endif %}
        
        <div style="color: var(--gray-color); font-size: 0.9em;">
            <i class="fas fa-tag"></i> {{ complaint.category }} |
            <i class="fas fa-flag"></i> {{ complaint.priority|title }}
            
            {% if complaint.assigned_officer %}
             | <i class="fas fa-user-tie"></i> Assigned to: {{ complaint.assigned_officer.username }}
            {% endif %}
        </div>
        
        {% if complaint.status == 'resolved' and complaint.resolution_details %}
        <div style="background: #d4edda; padding: 10px; border-radius: 5px; margin-top: 10px;">
            <h4><i class="fas fa-check-circle"></i> Resolution</h4>
            <p>{{ complaint.resolution_details }}</p>
            {% if complaint.resolved_image_path %}
            <img src="{{ url_for('uploaded_file', filename=complaint.resolved_image_path) }}" 
                 alt="Resolution Image" style="max-width: 200px; border-radius: 5px; margin-top: 10px;">
            {% endif %}
        </div>
        {% endif %}
    </div>
    {% endfor %}
{% else %}
<div class="card" style="text-align: center; padding: 40px;">
    <i class="fas fa-inbox fa-3x" style="color: var(--gray-color); margin-bottom: 20px;"></i>
    <h3>No Complaints Found</h3>
    <p>There are no complaints in the system.</p>
</div>
{% endif %}
{% endblock %}'''

# ============= INITIALIZATION =============
def init_app():
    """Initialize the application"""
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create default admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@municipal.gov',
                role='admin',
                taluka='Central'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created:")
            print("Username: admin")
            print("Password: admin123")
        
        # Create template files
        create_template_files()
        
        print("Application initialized successfully!")

# ============= MAIN =============
if __name__ == '__main__':
    # Initialize the application
    init_app()
    
    # Run the app
    print("\nStarting Municipal Complaint Management System...")
    print("Access the application at: http://localhost:5000")
    print("Admin login: admin / admin123")
    app.run(debug=True, host='0.0.0.0', port=5000)