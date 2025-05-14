"""
Utility functions for the CLI interface.
This module handles incident management API interactions.
"""
import os
import json
import requests
import logging
from typing import Dict, Any, Optional, List

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Base URL for API
BASE_URL = os.environ.get('API_URL', 'http://localhost:5000/api')

def list_incidents(token: str, status: Optional[str] = None) -> Dict[str, Any]:
    """
    List incidents through the API.
    
    Args:
        token: JWT authentication token
        status: Optional status filter
        
    Returns:
        Dictionary with list of incidents
    """
    try:
        # Build API URL with optional query parameters
        url = f"{BASE_URL}/incidents"
        params = {}
        if status:
            params['status'] = status
            
        # Make API request
        response = requests.get(
            url,
            params=params,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Check response
        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'message': 'Incidents retrieved successfully',
                'data': data
            }
        else:
            error_msg = response.json().get('error', 'Failed to retrieve incidents')
            logger.error(f"List incidents failed: {error_msg}")
            return {
                'success': False,
                'message': error_msg
            }
    
    except Exception as e:
        logger.error(f"List incidents error: {str(e)}")
        return {
            'success': False,
            'message': f"Error retrieving incidents: {str(e)}"
        }

def get_incident(token: str, incident_id: int) -> Dict[str, Any]:
    """
    Get details of a specific incident.
    
    Args:
        token: JWT authentication token
        incident_id: ID of the incident
        
    Returns:
        Dictionary with incident details
    """
    try:
        # Make API request
        response = requests.get(
            f"{BASE_URL}/incident/{incident_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Check response
        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'message': 'Incident retrieved successfully',
                'data': data
            }
        else:
            error_msg = response.json().get('error', 'Failed to retrieve incident')
            logger.error(f"Get incident failed: {error_msg}")
            return {
                'success': False,
                'message': error_msg
            }
    
    except Exception as e:
        logger.error(f"Get incident error: {str(e)}")
        return {
            'success': False,
            'message': f"Error retrieving incident: {str(e)}"
        }

def create_incident(token: str, incident_data) -> Dict[str, Any]:
    """
    Create a new incident.
    
    Args:
        token: JWT authentication token
        incident_data: Incident data object
        
    Returns:
        Dictionary with incident creation result
    """
    try:
        # Convert pydantic model to dict
        incident_dict = {
            'title': incident_data.title,
            'description': incident_data.description,
            'severity': incident_data.severity,
            'incident_type': incident_data.incident_type
        }
        
        # Make API request
        response = requests.post(
            f"{BASE_URL}/incidents",
            json=incident_dict,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Check response
        if response.status_code in [200, 201]:
            data = response.json()
            return {
                'success': True,
                'message': 'Incident created successfully',
                'data': data
            }
        else:
            error_msg = response.json().get('error', 'Failed to create incident')
            logger.error(f"Create incident failed: {error_msg}")
            return {
                'success': False,
                'message': error_msg
            }
    
    except Exception as e:
        logger.error(f"Create incident error: {str(e)}")
        return {
            'success': False,
            'message': f"Error creating incident: {str(e)}"
        }

def update_incident_status(token: str, incident_id: int, status: Optional[str] = None, 
                           severity: Optional[str] = None, title: Optional[str] = None) -> Dict[str, Any]:
    """
    Update an incident's status, severity, or title.
    
    Args:
        token: JWT authentication token
        incident_id: ID of the incident
        status: New status value (optional)
        severity: New severity value (optional)
        title: New title value (optional)
        
    Returns:
        Dictionary with update result
    """
    try:
        # Build update data
        update_data = {}
        if status:
            update_data['status'] = status
        if severity:
            update_data['severity'] = severity
        if title:
            update_data['title'] = title
            
        # Make API request
        response = requests.put(
            f"{BASE_URL}/incident/{incident_id}",
            json=update_data,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Check response
        if response.status_code == 200:
            return {
                'success': True,
                'message': 'Incident updated successfully',
                'data': response.json()
            }
        else:
            error_msg = response.json().get('error', 'Failed to update incident')
            logger.error(f"Update incident failed: {error_msg}")
            return {
                'success': False,
                'message': error_msg
            }
    
    except Exception as e:
        logger.error(f"Update incident error: {str(e)}")
        return {
            'success': False,
            'message': f"Error updating incident: {str(e)}"
        }

def add_incident_step(token: str, incident_id: int, action: str, notes: Optional[str] = None) -> Dict[str, Any]:
    """
    Add a response step to an incident.
    
    Args:
        token: JWT authentication token
        incident_id: ID of the incident
        action: Step action description
        notes: Additional notes (optional)
        
    Returns:
        Dictionary with step addition result
    """
    try:
        # Build step data
        step_data = {
            'action': action
        }
        if notes:
            step_data['notes'] = notes
            
        # Make API request
        response = requests.post(
            f"{BASE_URL}/incident/{incident_id}/steps",
            json=step_data,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Check response
        if response.status_code in [200, 201]:
            return {
                'success': True,
                'message': 'Response step added successfully',
                'data': response.json()
            }
        else:
            error_msg = response.json().get('error', 'Failed to add response step')
            logger.error(f"Add response step failed: {error_msg}")
            return {
                'success': False,
                'message': error_msg
            }
    
    except Exception as e:
        logger.error(f"Add response step error: {str(e)}")
        return {
            'success': False,
            'message': f"Error adding response step: {str(e)}"
        }

def list_templates(token: str) -> Dict[str, Any]:
    """
    List all incident response templates.
    
    Args:
        token: JWT authentication token
        
    Returns:
        Dictionary with templates
    """
    try:
        # Make API request
        response = requests.get(
            f"{BASE_URL}/templates",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Check response
        if response.status_code == 200:
            return {
                'success': True,
                'message': 'Templates retrieved successfully',
                'data': response.json()
            }
        else:
            error_msg = response.json().get('error', 'Failed to retrieve templates')
            logger.error(f"List templates failed: {error_msg}")
            return {
                'success': False,
                'message': error_msg
            }
    
    except Exception as e:
        logger.error(f"List templates error: {str(e)}")
        return {
            'success': False,
            'message': f"Error retrieving templates: {str(e)}"
        }
