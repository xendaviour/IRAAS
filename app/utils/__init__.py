"""
Utility functions for the Incident Response Tool.
"""
import logging
from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user

logger = logging.getLogger(__name__)

def admin_required(f):
    """Decorator to restrict access to admin users"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            logger.warning(f"Unauthorized admin access attempt by {current_user.username}")
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('main.unauthorized'))
        return f(*args, **kwargs)
    return decorated_function

# Severity levels for incidents
SEVERITY_LEVELS = {
    'Low': 1,
    'Medium': 2,
    'High': 3,
    'Critical': 4
}

# Status options for incidents
STATUS_OPTIONS = [
    'New',
    'Investigating',
    'Resolved',
    'Closed'
]

# Common incident types
INCIDENT_TYPES = [
    'Malware',
    'Phishing',
    'Data Breach',
    'DDoS',
    'Unauthorized Access',
    'Social Engineering',
    'Insider Threat',
    'Ransomware',
    'Other'
]

def format_datetime(dt):
    """Format datetime for display"""
    if not dt:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def get_template_for_incident(incident_type):
    """Get default template steps for an incident type"""
    from app.utils.template_generator import create_template_if_not_exists
    # First check if we have a template in the database
    # If not, fall back to the default basic steps
    
    # Default basic steps for common incident types
    DEFAULT_RESPONSE_TEMPLATES = {
        'Malware': [
            'Isolate affected systems from the network',
            'Identify the malware type and behavior',
            'Scan other systems for similar infections',
            'Remove malware and restore systems',
            'Investigate entry point and update security controls'
        ],
        'Phishing': [
            'Collect email headers and content',
            'Identify affected users and accounts',
            'Reset compromised credentials',
            'Block sender and similar patterns',
            'Conduct user security awareness training'
        ],
        'Data Breach': [
            'Identify compromised data and systems',
            'Isolate affected systems',
            'Determine breach method and timeline',
            'Notify affected parties and authorities',
            'Implement additional security controls'
        ],
        'DDoS': [
            'Confirm attack pattern and traffic characteristics',
            'Engage with ISP/hosting provider for traffic filtering',
            'Implement rate limiting and traffic filtering',
            'Scale resources to handle increased traffic',
            'Document attack patterns for future mitigation'
        ]
    }
    
    return DEFAULT_RESPONSE_TEMPLATES.get(incident_type, [])