#!/usr/bin/env python3
import os
import sys
import json
import click
import logging
from datetime import datetime

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cli.auth import register_user, login_user, validate_token
from cli.utils import create_incident, list_incidents, get_incident, update_incident_status, add_incident_step
from app.schemas import UserCreate, UserLogin, IncidentCreate

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('cli')

@click.group()
def cli():
    """Incident Response Tool Command Line Interface."""
    pass

# User Management Commands
@cli.group()
def auth():
    """User authentication commands."""
    pass

@auth.command('register')
@click.option('-u', '--username', required=True, help='Username for the new account')
@click.option('-e', '--email', required=True, help='Email address')
@click.option('-p', '--password', required=True, prompt=True, hide_input=True, 
              confirmation_prompt=True, help='Password for the new account')
def register_command(username, email, password):
    """Register a new user account."""
    try:
        # Validate input using UserCreate schema
        user_data = UserCreate(username=username, email=email, password=password)
        
        # Register user
        result = register_user(user_data)
        
        if result.get('success'):
            registration_token = result.get('data', {}).get('registration_token')
            click.echo(click.style('Registration successful!', fg='green'))
            click.echo(f"Username: {username}")
            click.echo(f"Registration Token: {registration_token}")
            click.echo("\nStore this registration token securely - you'll need it for authentication.")
        else:
            click.echo(click.style(f"Registration failed: {result.get('message')}", fg='red'))
    
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        click.echo(click.style(f"Registration error: {str(e)}", fg='red'))

@auth.command('login')
@click.option('-u', '--username', required=True, help='Username')
@click.option('-p', '--password', required=True, prompt=True, hide_input=True, help='Password')
def login_command(username, password):
    """Log in to your account and get an authentication token."""
    try:
        # Validate input using UserLogin schema
        login_data = UserLogin(username=username, password=password)
        
        # Login user
        result = login_user(login_data)
        
        if result.get('success'):
            token = result.get('data', {}).get('access_token')
            user_id = result.get('data', {}).get('user_id')
            
            # Save token to config file
            config_dir = os.path.expanduser('~/.incidentresponse')
            os.makedirs(config_dir, exist_ok=True)
            
            with open(os.path.join(config_dir, 'config.json'), 'w') as f:
                json.dump({
                    'token': token,
                    'username': username,
                    'user_id': user_id
                }, f)
            
            click.echo(click.style('Login successful!', fg='green'))
            click.echo("Authentication token has been saved to your config file.")
        else:
            click.echo(click.style(f"Login failed: {result.get('message')}", fg='red'))
    
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        click.echo(click.style(f"Login error: {str(e)}", fg='red'))

@auth.command('validate-token')
@click.option('-t', '--token', required=True, help='Registration token to validate')
@click.option('-u', '--username', required=True, help='Username')
def validate_token_command(token, username):
    """Validate a registration token."""
    try:
        # Validate token
        result = validate_token(token, username)
        
        if result.get('success'):
            click.echo(click.style('Token is valid!', fg='green'))
        else:
            click.echo(click.style(f"Token validation failed: {result.get('message')}", fg='red'))
    
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        click.echo(click.style(f"Token validation error: {str(e)}", fg='red'))

# Incident Management Commands
@cli.group()
def incidents():
    """Incident management commands."""
    pass

@incidents.command('list')
@click.option('--all', is_flag=True, help='Show all incidents')
@click.option('--status', help='Filter incidents by status')
def list_incidents_command(all, status):
    """List all incidents."""
    try:
        # Get user token
        config_file = os.path.expanduser('~/.incidentresponse/config.json')
        if not os.path.exists(config_file):
            click.echo(click.style("You need to log in first. Use 'auth login' command.", fg='red'))
            return
        
        with open(config_file, 'r') as f:
            config = json.load(f)
            token = config.get('token')
        
        # List incidents
        result = list_incidents(token, status)
        
        if result.get('success'):
            incidents = result.get('data', {}).get('incidents', [])
            
            if not incidents:
                click.echo("No incidents found.")
                return
            
            click.echo(click.style("Incidents:", fg='blue', bold=True))
            click.echo(click.style("=" * 80, fg='blue'))
            
            for incident in incidents:
                status_color = {
                    'New': 'blue',
                    'Investigating': 'yellow',
                    'Resolved': 'green',
                    'Closed': 'white'
                }.get(incident.get('status'), 'white')
                
                click.echo(
                    f"[{incident.get('id')}] "
                    + click.style(f"{incident.get('title')}", bold=True)
                    + f" - Type: {incident.get('incident_type')}"
                    + f", Severity: {incident.get('severity')}"
                    + f", Status: " + click.style(f"{incident.get('status')}", fg=status_color)
                )
            
            click.echo(click.style("=" * 80, fg='blue'))
        else:
            click.echo(click.style(f"Failed to list incidents: {result.get('message')}", fg='red'))
    
    except Exception as e:
        logger.error(f"List incidents error: {str(e)}")
        click.echo(click.style(f"Error: {str(e)}", fg='red'))

@incidents.command('view')
@click.argument('incident_id', type=int)
def view_incident_command(incident_id):
    """View details of a specific incident."""
    try:
        # Get user token
        config_file = os.path.expanduser('~/.incidentresponse/config.json')
        if not os.path.exists(config_file):
            click.echo(click.style("You need to log in first. Use 'auth login' command.", fg='red'))
            return
        
        with open(config_file, 'r') as f:
            config = json.load(f)
            token = config.get('token')
        
        # Get incident details
        result = get_incident(token, incident_id)
        
        if result.get('success'):
            incident = result.get('data', {})
            responses = incident.get('responses', [])
            
            # Display incident header
            status_color = {
                'New': 'blue',
                'Investigating': 'yellow',
                'Resolved': 'green',
                'Closed': 'white'
            }.get(incident.get('status'), 'white')
            
            click.echo("\n" + click.style("=" * 80, fg='blue'))
            click.echo(click.style(f"Incident #{incident.get('id')}: {incident.get('title')}", fg='blue', bold=True))
            click.echo(click.style("=" * 80, fg='blue'))
            
            # Display incident details
            click.echo(f"Type:        {incident.get('incident_type')}")
            click.echo(f"Severity:    {incident.get('severity')}")
            click.echo(f"Status:      " + click.style(f"{incident.get('status')}", fg=status_color))
            click.echo(f"Created:     {incident.get('created_at')}")
            click.echo(f"Updated:     {incident.get('updated_at')}")
            
            # Display description
            click.echo("\n" + click.style("Description:", bold=True))
            click.echo(f"{incident.get('description') or 'No description provided.'}")
            
            # Display response steps
            click.echo("\n" + click.style("Response Steps:", bold=True))
            if responses:
                for step in responses:
                    step_status = "[✓]" if step.get('completed') else "[ ]"
                    
                    click.echo(f"\n{step_status} Step {step.get('step_number')}: " + 
                               click.style(f"{step.get('action')}", bold=True))
                    
                    if step.get('notes'):
                        click.echo(f"    Notes: {step.get('notes')}")
                    
                    if step.get('completed'):
                        click.echo(f"    Completed: {step.get('completed_at')}")
            else:
                click.echo("No response steps found.")
            
            click.echo(click.style("\n" + "=" * 80, fg='blue'))
        else:
            click.echo(click.style(f"Failed to retrieve incident: {result.get('message')}", fg='red'))
    
    except Exception as e:
        logger.error(f"View incident error: {str(e)}")
        click.echo(click.style(f"Error: {str(e)}", fg='red'))

@incidents.command('create')
@click.option('--title', required=True, help='Incident title')
@click.option('--type', 'incident_type', required=True, help='Incident type')
@click.option('--severity', default='Medium', 
              type=click.Choice(['Low', 'Medium', 'High', 'Critical']), 
              help='Incident severity')
@click.option('--description', help='Incident description')
def create_incident_command(title, incident_type, severity, description):
    """Create a new incident."""
    try:
        # Get user token
        config_file = os.path.expanduser('~/.incidentresponse/config.json')
        if not os.path.exists(config_file):
            click.echo(click.style("You need to log in first. Use 'auth login' command.", fg='red'))
            return
        
        with open(config_file, 'r') as f:
            config = json.load(f)
            token = config.get('token')
        
        # Create incident data
        incident_data = IncidentCreate(
            title=title,
            incident_type=incident_type,
            severity=severity,
            description=description
        )
        
        # Create incident
        result = create_incident(token, incident_data)
        
        if result.get('success'):
            incident = result.get('data', {})
            click.echo(click.style("Incident created successfully!", fg='green'))
            click.echo(f"Incident ID: {incident.get('id')}")
            click.echo(f"Title: {incident.get('title')}")
            click.echo(f"Status: {incident.get('status')}")
        else:
            click.echo(click.style(f"Failed to create incident: {result.get('message')}", fg='red'))
    
    except Exception as e:
        logger.error(f"Create incident error: {str(e)}")
        click.echo(click.style(f"Error: {str(e)}", fg='red'))

@incidents.command('update')
@click.argument('incident_id', type=int)
@click.option('--status', help='Update incident status')
@click.option('--severity', type=click.Choice(['Low', 'Medium', 'High', 'Critical']), help='Update incident severity')
@click.option('--title', help='Update incident title')
def update_incident_command(incident_id, status, severity, title):
    """Update an incident's status, severity, or title."""
    try:
        # Get user token
        config_file = os.path.expanduser('~/.incidentresponse/config.json')
        if not os.path.exists(config_file):
            click.echo(click.style("You need to log in first. Use 'auth login' command.", fg='red'))
            return
        
        with open(config_file, 'r') as f:
            config = json.load(f)
            token = config.get('token')
        
        # Update incident
        result = update_incident_status(token, incident_id, status, severity, title)
        
        if result.get('success'):
            click.echo(click.style("Incident updated successfully!", fg='green'))
        else:
            click.echo(click.style(f"Failed to update incident: {result.get('message')}", fg='red'))
    
    except Exception as e:
        logger.error(f"Update incident error: {str(e)}")
        click.echo(click.style(f"Error: {str(e)}", fg='red'))

@incidents.command('add-step')
@click.argument('incident_id', type=int)
@click.option('--action', required=True, help='Step action description')
@click.option('--notes', help='Additional notes for the step')
def add_step_command(incident_id, action, notes):
    """Add a response step to an incident."""
    try:
        # Get user token
        config_file = os.path.expanduser('~/.incidentresponse/config.json')
        if not os.path.exists(config_file):
            click.echo(click.style("You need to log in first. Use 'auth login' command.", fg='red'))
            return
        
        with open(config_file, 'r') as f:
            config = json.load(f)
            token = config.get('token')
        
        # Add step
        result = add_incident_step(token, incident_id, action, notes)
        
        if result.get('success'):
            click.echo(click.style("Response step added successfully!", fg='green'))
        else:
            click.echo(click.style(f"Failed to add response step: {result.get('message')}", fg='red'))
    
    except Exception as e:
        logger.error(f"Add step error: {str(e)}")
        click.echo(click.style(f"Error: {str(e)}", fg='red'))

if __name__ == '__main__':
    cli()
