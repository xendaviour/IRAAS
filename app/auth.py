import logging
import secrets
from datetime import datetime, timedelta

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

from app import db
from app.models import User
from app.schemas import UserCreate, UserLogin, Token
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)

# Create blueprint
auth_bp = Blueprint('auth', __name__)

def generate_registration_token():
    """Generate a secure registration token"""
    return secrets.token_urlsafe(32)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        
        # Validate input
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('register.html')
        
        if password != password_confirm:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return render_template('register.html')
        
        # Create new user
        try:
            user = User(username=username, email=email)
            user.set_password(password)
            
            # Generate registration token
            registration_token = generate_registration_token()
            user.registration_token = registration_token
            
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! You can now log in.', 'success')
            logger.info(f"User {username} registered successfully")
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration', 'danger')
            return render_template('register.html')
    
    # GET request - display the form
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validate input
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')
        
        # Check if user exists
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
        
        # Log user in
        login_user(user)
        flash('Login successful!', 'success')
        logger.info(f"User {username} logged in")
        
        # Redirect to the requested page or dashboard
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('main.dashboard'))
    
    # GET request - display the form
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    """User logout route"""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('main.index'))

# API Routes for CLI integration
@auth_bp.route('/api/register', methods=['POST'])
def api_register():
    """API endpoint for user registration"""
    data = request.get_json()
    
    try:
        # Validate input using UserCreate schema
        user_data = UserCreate(**data)
        
        # Check if username or email already exists
        if User.query.filter_by(username=user_data.username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=user_data.email).first():
            return jsonify({'error': 'Email already exists'}), 400
        
        # Create new user
        user = User(username=user_data.username, email=user_data.email)
        user.set_password(user_data.password)
        
        # Generate registration token
        registration_token = generate_registration_token()
        user.registration_token = registration_token
        
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"User {user_data.username} registered via API")
        return jsonify({
            'message': 'Registration successful',
            'username': user.username,
            'registration_token': registration_token
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"API registration error: {str(e)}")
        return jsonify({'error': str(e)}), 400

@auth_bp.route('/api/login', methods=['POST'])
def api_login():
    """API endpoint for user login"""
    data = request.get_json()
    
    try:
        # Validate input using UserLogin schema
        login_data = UserLogin(**data)
        
        # Check if user exists
        user = User.query.filter_by(username=login_data.username).first()
        if not user or not user.check_password(login_data.password):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Generate JWT token with string identity (user_id as string)
        access_token = create_access_token(
            identity=str(user.id),
            expires_delta=timedelta(days=1)
        )
        
        logger.info(f"User {login_data.username} logged in via API")
        return jsonify({
            'access_token': access_token,
            'token_type': 'bearer',
            'user_id': user.id,
            'username': user.username
        }), 200
        
    except Exception as e:
        logger.error(f"API login error: {str(e)}")
        return jsonify({'error': str(e)}), 400

@auth_bp.route('/api/user', methods=['GET'])
@jwt_required()
def api_get_user():
    """API endpoint to get user details"""
    identity = get_jwt_identity()
    user_id = identity.get('user_id')
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin
    }), 200

@auth_bp.route('/api/token/validate', methods=['POST'])
def api_validate_token():
    """API endpoint to validate registration token"""
    data = request.get_json()
    token = data.get('token')
    username = data.get('username')
    
    if not token or not username:
        return jsonify({'error': 'Token and username are required'}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.registration_token != token:
        return jsonify({'error': 'Invalid token'}), 401
    
    return jsonify({'message': 'Token is valid', 'username': username}), 200
