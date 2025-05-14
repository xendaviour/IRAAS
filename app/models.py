from datetime import datetime, timedelta
from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    """User model for authentication and user management"""
    __tablename__ = 'users'
    
    id = db.Column(Integer, primary_key=True)
    username = db.Column(String(64), unique=True, nullable=False, index=True)
    email = db.Column(String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(String(256), nullable=False)
    is_active = db.Column(Boolean, default=True)
    is_admin = db.Column(Boolean, default=False)
    registration_token = db.Column(String(256), nullable=True)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    incidents = db.relationship('Incident', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        """Generate hashed password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches the hash"""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class Incident(db.Model):
    """Model for security incidents"""
    __tablename__ = 'incidents'
    
    id = db.Column(Integer, primary_key=True)
    title = db.Column(String(120), nullable=False)
    description = db.Column(Text, nullable=True)
    severity = db.Column(String(20), default='Medium')
    status = db.Column(String(20), default='New')
    incident_type = db.Column(String(50), nullable=False)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Relationships
    responses = db.relationship('IncidentResponse', backref='incident', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f"<Incident {self.title}>"


class IncidentResponse(db.Model):
    """Model for incident response steps"""
    __tablename__ = 'incident_responses'
    
    id = db.Column(Integer, primary_key=True)
    step_number = db.Column(Integer, nullable=False)
    action = db.Column(Text, nullable=False)
    notes = db.Column(Text, nullable=True)
    completed = db.Column(Boolean, default=False)
    completed_at = db.Column(DateTime, nullable=True)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    incident_id = db.Column(Integer, ForeignKey('incidents.id'), nullable=False)
    
    def __repr__(self):
        return f"<Response {self.step_number} for Incident {self.incident_id}>"


class IncidentTemplate(db.Model):
    """Model for predefined incident response templates"""
    __tablename__ = 'incident_templates'
    
    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(120), nullable=False)
    description = db.Column(Text, nullable=True)
    incident_type = db.Column(String(50), nullable=False)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    steps = db.relationship('TemplateStep', backref='template', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f"<Template {self.name}>"


class TemplateStep(db.Model):
    """Model for steps within incident templates"""
    __tablename__ = 'template_steps'
    
    id = db.Column(Integer, primary_key=True)
    step_number = db.Column(Integer, nullable=False)
    action = db.Column(Text, nullable=False)
    description = db.Column(Text, nullable=True)
    template_id = db.Column(Integer, ForeignKey('incident_templates.id'), nullable=False)
    
    def __repr__(self):
        return f"<TemplateStep {self.step_number} for Template {self.template_id}>"
