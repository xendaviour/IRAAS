"""
Authentication utility functions for the CLI interface.
This module handles the user registration, login, and token validation processes.
"""
import os
import json
import requests
import logging
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Base URL for API
BASE_URL = os.environ.get('API_URL', 'http://localhost:5000/api')

def register_user(user_data) -> Dict[str, Any]:
    """
    Register a new user through the API.
    
    Args:
        user_data: A UserCreate schema object with username, email, and password
        
    Returns:
        Dictionary with registration result
    """
    try:
        # Convert pydantic model to dict
        user_dict = {
            'username': user_data.username,
            'email': user_data.email,
            'password': user_data.password
        }
        
        # Make API request
        response = requests.post(
            f"{BASE_URL}/register",
            json=user_dict
        )
        
        # Check response
        if response.status_code == 201:
            data = response.json()
            logger.info(f"User {user_data.username} registered successfully")
            return {
                'success': True,
                'message': 'Registration successful',
                'data': {
                    'username': data.get('username'),
                    'registration_token': data.get('registration_token')
                }
            }
        else:
            error_msg = response.json().get('error', 'Unknown error')
            logger.error(f"Registration failed: {error_msg}")
            return {
                'success': False,
                'message': f"Registration failed: {error_msg}"
            }
    
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return {
            'success': False,
            'message': f"Registration error: {str(e)}"
        }

def login_user(login_data) -> Dict[str, Any]:
    """
    Log in a user and retrieve an authentication token.
    
    Args:
        login_data: A UserLogin schema object with username and password
        
    Returns:
        Dictionary with login result
    """
    try:
        # Convert pydantic model to dict
        login_dict = {
            'username': login_data.username,
            'password': login_data.password
        }
        
        # Make API request
        response = requests.post(
            f"{BASE_URL}/login",
            json=login_dict
        )
        
        # Check response
        if response.status_code == 200:
            data = response.json()
            logger.info(f"User {login_data.username} logged in successfully")
            return {
                'success': True,
                'message': 'Login successful',
                'data': {
                    'username': data.get('username'),
                    'user_id': data.get('user_id'),
                    'access_token': data.get('access_token'),
                    'token_type': data.get('token_type')
                }
            }
        else:
            error_msg = response.json().get('error', 'Invalid credentials')
            logger.error(f"Login failed: {error_msg}")
            return {
                'success': False,
                'message': f"Login failed: {error_msg}"
            }
    
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return {
            'success': False,
            'message': f"Login error: {str(e)}"
        }

def validate_token(token: str, username: str) -> Dict[str, Any]:
    """
    Validate a registration token.
    
    Args:
        token: The registration token to validate
        username: The username associated with the token
        
    Returns:
        Dictionary with validation result
    """
    try:
        # Make API request
        response = requests.post(
            f"{BASE_URL}/token/validate",
            json={
                'token': token,
                'username': username
            }
        )
        
        # Check response
        if response.status_code == 200:
            logger.info(f"Token for user {username} validated successfully")
            return {
                'success': True,
                'message': 'Token is valid',
                'data': {
                    'username': username
                }
            }
        else:
            error_msg = response.json().get('error', 'Invalid token')
            logger.error(f"Token validation failed: {error_msg}")
            return {
                'success': False,
                'message': f"Token validation failed: {error_msg}"
            }
    
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        return {
            'success': False,
            'message': f"Token validation error: {str(e)}"
        }

def get_user_details(token: str) -> Dict[str, Any]:
    """
    Get user details using a JWT token.
    
    Args:
        token: JWT authentication token
        
    Returns:
        Dictionary with user details
    """
    try:
        # Make API request
        response = requests.get(
            f"{BASE_URL}/user",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Check response
        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'message': 'User details retrieved successfully',
                'data': data
            }
        else:
            error_msg = response.json().get('error', 'Failed to retrieve user details')
            logger.error(f"Get user details failed: {error_msg}")
            return {
                'success': False,
                'message': error_msg
            }
    
    except Exception as e:
        logger.error(f"Get user details error: {str(e)}")
        return {
            'success': False,
            'message': f"Error retrieving user details: {str(e)}"
        }
