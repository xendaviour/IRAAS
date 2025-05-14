import logging
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request, abort
from flask_login import login_required, current_user
from flask_jwt_extended import jwt_required, get_jwt_identity

from app import db
from app.models import User, Incident, IncidentResponse, IncidentTemplate, TemplateStep
from app.utils import admin_required

logger = logging.getLogger(__name__)

# Create blueprint
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Homepage route"""
    return render_template('index.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard route, showing user's incidents"""
    incidents = Incident.query.filter_by(user_id=current_user.id).order_by(Incident.created_at.desc()).all()
    return render_template('dashboard.html', incidents=incidents)

@main_bp.route('/incidents/new', methods=['GET', 'POST'])
@login_required
def new_incident():
    """Create a new incident"""
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        severity = request.form.get('severity')
        incident_type = request.form.get('incident_type')
        template_id = request.form.get('template_id')
        
        if not title or not incident_type:
            flash('Title and incident type are required', 'danger')
            return redirect(url_for('main.new_incident'))
        
        # Create new incident
        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            incident_type=incident_type,
            user_id=current_user.id
        )
        db.session.add(incident)
        db.session.commit()
        
        # If a template was selected, apply the template steps
        if template_id:
            template = IncidentTemplate.query.get(template_id)
            if template:
                for step in template.steps:
                    response_step = IncidentResponse(
                        step_number=step.step_number,
                        action=step.action,
                        notes=step.description,
                        incident_id=incident.id
                    )
                    db.session.add(response_step)
                db.session.commit()
                logger.info(f"Applied template '{template.name}' to incident '{incident.title}'")
        else:
            # If no template was selected but the incident type matches one of our predefined templates,
            # find a matching template by incident_type
            matching_template = IncidentTemplate.query.filter_by(incident_type=incident_type).first()
            if matching_template:
                for step in matching_template.steps:
                    response_step = IncidentResponse(
                        step_number=step.step_number,
                        action=step.action,
                        notes=step.description,
                        incident_id=incident.id
                    )
                    db.session.add(response_step)
                db.session.commit()
                logger.info(f"Auto-applied matching template '{matching_template.name}' to incident '{incident.title}'")
                flash(f"Applied '{matching_template.name}' template based on incident type", 'info')
        
        flash('Incident created successfully', 'success')
        return redirect(url_for('main.view_incident', incident_id=incident.id))
    
    # GET request - display the form
    templates = IncidentTemplate.query.all()
    incident_types = []
    
    # Get unique incident types from templates
    template_types = db.session.query(IncidentTemplate.incident_type).distinct().all()
    for template_type in template_types:
        if template_type[0] not in incident_types:
            incident_types.append(template_type[0])
    
    # Add other incident types from the constants
    from app.utils import INCIDENT_TYPES
    for incident_type in INCIDENT_TYPES:
        if incident_type not in incident_types:
            incident_types.append(incident_type)
    
    return render_template('incident_response.html', 
                          templates=templates, 
                          incident=None,
                          incident_types=incident_types)

@main_bp.route('/incidents/<int:incident_id>')
@login_required
def view_incident(incident_id):
    """View an incident and its response steps"""
    incident = Incident.query.get_or_404(incident_id)
    
    # Ensure the user has permission to view this incident
    if incident.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view this incident', 'danger')
        return redirect(url_for('main.dashboard'))
    
    responses = IncidentResponse.query.filter_by(incident_id=incident_id).order_by(IncidentResponse.step_number).all()
    return render_template('incident_response.html', incident=incident, responses=responses)

@main_bp.route('/incidents/<int:incident_id>/update', methods=['POST'])
@login_required
def update_incident(incident_id):
    """Update incident details"""
    incident = Incident.query.get_or_404(incident_id)
    
    # Ensure the user has permission to update this incident
    if incident.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to modify this incident', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Update fields
    incident.title = request.form.get('title', incident.title)
    incident.description = request.form.get('description', incident.description)
    incident.severity = request.form.get('severity', incident.severity)
    incident.status = request.form.get('status', incident.status)
    incident.updated_at = datetime.utcnow()
    
    db.session.commit()
    flash('Incident updated successfully', 'success')
    return redirect(url_for('main.view_incident', incident_id=incident_id))

@main_bp.route('/incidents/<int:incident_id>/add_step', methods=['POST'])
@login_required
def add_response_step(incident_id):
    """Add a new response step to an incident"""
    incident = Incident.query.get_or_404(incident_id)
    
    # Ensure the user has permission
    if incident.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to modify this incident', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Get highest step number
    highest_step = db.session.query(db.func.max(IncidentResponse.step_number)).filter_by(incident_id=incident_id).scalar() or 0
    
    # Create new step
    step = IncidentResponse(
        step_number=highest_step + 1,
        action=request.form.get('action'),
        notes=request.form.get('notes'),
        incident_id=incident_id
    )
    db.session.add(step)
    db.session.commit()
    
    flash('Response step added successfully', 'success')
    return redirect(url_for('main.view_incident', incident_id=incident_id))

@main_bp.route('/incidents/<int:incident_id>/step/<int:step_id>/update', methods=['POST'])
@login_required
def update_response_step(incident_id, step_id):
    """Update a response step"""
    step = IncidentResponse.query.get_or_404(step_id)
    incident = Incident.query.get_or_404(incident_id)
    
    # Ensure the user has permission
    if incident.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to modify this incident', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Update fields
    step.action = request.form.get('action', step.action)
    step.notes = request.form.get('notes', step.notes)
    
    # Handle completion toggle
    completed = request.form.get('completed', 'off') == 'on'
    if completed and not step.completed:
        step.completed = True
        step.completed_at = datetime.utcnow()
    elif not completed:
        step.completed = False
        step.completed_at = None
    
    db.session.commit()
    flash('Response step updated successfully', 'success')
    return redirect(url_for('main.view_incident', incident_id=incident_id))

@main_bp.route('/templates')
@login_required
def list_templates():
    """List all incident response templates"""
    templates = IncidentTemplate.query.all()
    return render_template('templates.html', templates=templates)

@main_bp.route('/templates/<int:template_id>')
@login_required
def view_template(template_id):
    """View a template and its steps"""
    template = IncidentTemplate.query.get_or_404(template_id)
    steps = TemplateStep.query.filter_by(template_id=template_id).order_by(TemplateStep.step_number).all()
    return render_template('template_view.html', template=template, steps=steps)

@main_bp.route('/templates/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_template():
    """Create a new incident response template"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        incident_type = request.form.get('incident_type')
        
        if not name or not incident_type:
            flash('Name and incident type are required', 'danger')
            return redirect(url_for('main.new_template'))
        
        # Create new template
        template = IncidentTemplate(
            name=name,
            description=description,
            incident_type=incident_type
        )
        db.session.add(template)
        db.session.commit()
        flash('Template created successfully', 'success')
        return redirect(url_for('main.view_template', template_id=template.id))
    
    return render_template('template_new.html')

@main_bp.route('/templates/<int:template_id>/add_step', methods=['POST'])
@login_required
@admin_required
def add_template_step(template_id):
    """Add a step to a template"""
    template = IncidentTemplate.query.get_or_404(template_id)
    
    # Get highest step number
    highest_step = db.session.query(db.func.max(TemplateStep.step_number)).filter_by(template_id=template_id).scalar() or 0
    
    # Create new step
    step = TemplateStep(
        step_number=highest_step + 1,
        action=request.form.get('action'),
        description=request.form.get('description'),
        template_id=template_id
    )
    db.session.add(step)
    db.session.commit()
    
    flash('Template step added successfully', 'success')
    return redirect(url_for('main.view_template', template_id=template_id))

# API endpoints for CLI integration
@main_bp.route('/api/incidents', methods=['GET'])
@jwt_required()
def api_list_incidents():
    """API endpoint to list user's incidents"""
    # Get user ID from JWT token (as string)
    user_id_str = get_jwt_identity()
    # Convert to integer
    user_id = int(user_id_str) if user_id_str else None
    
    incidents = Incident.query.filter_by(user_id=user_id).order_by(Incident.created_at.desc()).all()
    
    result = []
    for incident in incidents:
        result.append({
            'id': incident.id,
            'title': incident.title,
            'status': incident.status,
            'severity': incident.severity,
            'incident_type': incident.incident_type,
            'created_at': incident.created_at.isoformat()
        })
    
    return jsonify({'incidents': result})

@main_bp.route('/api/incident/<int:incident_id>', methods=['GET'])
@jwt_required()
def api_get_incident(incident_id):
    """API endpoint to get incident details"""
    # Get user ID from JWT token (as string)
    user_id_str = get_jwt_identity()
    # Convert to integer
    user_id = int(user_id_str) if user_id_str else None
    
    # Check if the user is admin
    user = User.query.get(user_id) if user_id else None
    is_admin = user.is_admin if user else False
    
    incident = Incident.query.get_or_404(incident_id)
    
    # Ensure the user has permission
    if incident.user_id != user_id and not is_admin:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    responses = IncidentResponse.query.filter_by(incident_id=incident_id).order_by(IncidentResponse.step_number).all()
    
    response_list = []
    for resp in responses:
        response_list.append({
            'id': resp.id,
            'step_number': resp.step_number,
            'action': resp.action,
            'notes': resp.notes,
            'completed': resp.completed,
            'completed_at': resp.completed_at.isoformat() if resp.completed_at else None
        })
    
    result = {
        'id': incident.id,
        'title': incident.title,
        'description': incident.description,
        'status': incident.status,
        'severity': incident.severity,
        'incident_type': incident.incident_type,
        'created_at': incident.created_at.isoformat(),
        'updated_at': incident.updated_at.isoformat(),
        'responses': response_list
    }
    
    # Check if analysis is requested
    include_analysis = request.args.get('include_analysis', 'false').lower() == 'true'
    if include_analysis:
        from app.utils.incident_analyzer import generate_incident_summary
        analysis = generate_incident_summary(incident, responses)
        result['analysis'] = analysis
    
    return jsonify(result)

@main_bp.route('/api/incident/<int:incident_id>/analysis', methods=['GET'])
@jwt_required()
def api_get_incident_analysis(incident_id):
    """API endpoint to get incident analysis"""
    # Get user ID from JWT token (as string)
    user_id_str = get_jwt_identity()
    # Convert to integer
    user_id = int(user_id_str) if user_id_str else None
    
    # Check if the user is admin
    user = User.query.get(user_id) if user_id else None
    is_admin = user.is_admin if user else False
    
    incident = Incident.query.get_or_404(incident_id)
    
    # Ensure the user has permission
    if incident.user_id != user_id and not is_admin:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    responses = IncidentResponse.query.filter_by(incident_id=incident_id).order_by(IncidentResponse.step_number).all()
    
    # Generate the analysis
    from app.utils.incident_analyzer import generate_incident_summary
    analysis = generate_incident_summary(incident, responses)
    
    return jsonify(analysis)

@main_bp.route('/api/templates', methods=['GET'])
@jwt_required()
def api_list_templates():
    """API endpoint to list templates"""
    templates = IncidentTemplate.query.all()
    include_steps = request.args.get('include_steps', 'false').lower() == 'true'
    
    result = []
    for template in templates:
        template_data = {
            'id': template.id,
            'name': template.name,
            'incident_type': template.incident_type,
            'description': template.description
        }
        
        # Include detailed steps if requested
        if include_steps:
            steps = []
            for step in template.steps.order_by(TemplateStep.step_number).all():
                steps.append({
                    'step_number': step.step_number,
                    'action': step.action,
                    'description': step.description
                })
            template_data['steps'] = steps
            
        result.append(template_data)
    
    return jsonify({'templates': result})

@main_bp.route('/api/templates/<string:incident_type>', methods=['GET'])
@jwt_required()
def api_get_templates_by_type(incident_type):
    """API endpoint to get templates for a specific incident type"""
    templates = IncidentTemplate.query.filter_by(incident_type=incident_type).all()
    
    if not templates:
        return jsonify({'error': f'No templates found for incident type: {incident_type}'}), 404
    
    result = []
    for template in templates:
        template_data = {
            'id': template.id,
            'name': template.name,
            'incident_type': template.incident_type,
            'description': template.description,
            'steps': []
        }
        
        # Always include steps for this endpoint
        for step in template.steps.order_by(TemplateStep.step_number).all():
            template_data['steps'].append({
                'step_number': step.step_number,
                'action': step.action,
                'description': step.description
            })
            
        result.append(template_data)
    
    return jsonify({'templates': result})

@main_bp.route('/api/incidents', methods=['POST'])
@jwt_required()
def api_create_incident():
    """API endpoint to create a new incident"""
    # Get user ID from JWT token (as string)
    user_id_str = get_jwt_identity()
    # Convert to integer
    user_id = int(user_id_str) if user_id_str else None
    
    if not user_id:
        return jsonify({'error': 'Invalid authentication token'}), 401
    
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('title') or not data.get('incident_type'):
            return jsonify({'error': 'Title and incident type are required'}), 400
        
        # Create incident
        incident = Incident(
            title=data.get('title'),
            description=data.get('description'),
            severity=data.get('severity', 'Medium'),
            incident_type=data.get('incident_type'),
            user_id=user_id
        )
        
        db.session.add(incident)
        db.session.commit()
        
        # Check for template
        if data.get('template_id'):
            template = IncidentTemplate.query.get(data.get('template_id'))
            if template:
                for step in template.steps:
                    response_step = IncidentResponse(
                        step_number=step.step_number,
                        action=step.action,
                        notes=step.description,
                        incident_id=incident.id
                    )
                    db.session.add(response_step)
                db.session.commit()
                logger.info(f"API: Applied template '{template.name}' to incident '{incident.title}'")
        else:
            # If no template was selected but the incident type matches one of our predefined templates,
            # find a matching template by incident_type
            matching_template = IncidentTemplate.query.filter_by(incident_type=incident.incident_type).first()
            if matching_template:
                for step in matching_template.steps:
                    response_step = IncidentResponse(
                        step_number=step.step_number,
                        action=step.action,
                        notes=step.description,
                        incident_id=incident.id
                    )
                    db.session.add(response_step)
                db.session.commit()
                logger.info(f"API: Auto-applied matching template '{matching_template.name}' to incident '{incident.title}'")
        
        return jsonify({
            'id': incident.id,
            'title': incident.title,
            'status': incident.status,
            'severity': incident.severity,
            'incident_type': incident.incident_type,
            'created_at': incident.created_at.isoformat()
        }), 201
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"API create incident error: {str(e)}")
        return jsonify({'error': str(e)}), 400

@main_bp.route('/api/incident/<int:incident_id>/steps', methods=['POST'])
@jwt_required()
def api_add_incident_step(incident_id):
    """API endpoint to add a step to an incident"""
    # Get user ID from JWT token (as string)
    user_id_str = get_jwt_identity()
    # Convert to integer
    user_id = int(user_id_str) if user_id_str else None
    
    # Get incident
    incident = Incident.query.get_or_404(incident_id)
    
    # Verify user has permission
    user = User.query.get(user_id) if user_id else None
    is_admin = user.is_admin if user else False
    
    if incident.user_id != user_id and not is_admin:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('action'):
            return jsonify({'error': 'Action is required'}), 400
        
        # Calculate next step number
        max_step = db.session.query(db.func.max(IncidentResponse.step_number))\
            .filter_by(incident_id=incident_id).scalar() or 0
        next_step = max_step + 1
        
        # Create response step
        step = IncidentResponse(
            step_number=data.get('step_number', next_step),
            action=data.get('action'),
            notes=data.get('notes'),
            completed=data.get('completed', False),
            incident_id=incident_id
        )
        
        db.session.add(step)
        db.session.commit()
        
        return jsonify({
            'id': step.id,
            'step_number': step.step_number,
            'action': step.action,
            'notes': step.notes,
            'completed': step.completed,
            'created_at': step.created_at.isoformat()
        }), 201
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"API add incident step error: {str(e)}")
        return jsonify({'error': str(e)}), 400

@main_bp.route('/api/incident/<int:incident_id>', methods=['PUT', 'PATCH'])
@jwt_required()
def api_update_incident(incident_id):
    """API endpoint to update an incident"""
    # Get user ID from JWT token (as string)
    user_id_str = get_jwt_identity()
    # Convert to integer
    user_id = int(user_id_str) if user_id_str else None
    
    # Get incident
    incident = Incident.query.get_or_404(incident_id)
    
    # Verify user has permission
    user = User.query.get(user_id) if user_id else None
    is_admin = user.is_admin if user else False
    
    if incident.user_id != user_id and not is_admin:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    try:
        data = request.get_json()
        
        # Update fields that were provided
        if 'title' in data and data['title']:
            incident.title = data['title']
        
        if 'description' in data:
            incident.description = data['description']
            
        if 'severity' in data and data['severity'] in ['Low', 'Medium', 'High', 'Critical']:
            incident.severity = data['severity']
            
        if 'status' in data and data['status'] in ['New', 'Investigating', 'Resolved', 'Closed']:
            incident.status = data['status']
            
        if 'incident_type' in data and data['incident_type']:
            incident.incident_type = data['incident_type']
        
        # Update timestamp
        incident.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'id': incident.id,
            'title': incident.title,
            'description': incident.description,
            'status': incident.status,
            'severity': incident.severity,
            'incident_type': incident.incident_type,
            'updated_at': incident.updated_at.isoformat()
        }), 200
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"API update incident error: {str(e)}")
        return jsonify({'error': str(e)}), 400

@main_bp.route('/db-health')
def db_health():
    """Database health check endpoint"""
    try:
        # Execute a simple query to test database connectivity
        result = db.session.execute(db.select(db.text("1"))).scalar()
        if result == 1:
            return jsonify({"status": "healthy", "message": "Database connection successful"})
        else:
            return jsonify({"status": "unhealthy", "message": "Database returned unexpected result"}), 500
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        return jsonify({"status": "unhealthy", "message": f"Database connection failed: {str(e)}"}), 500

@main_bp.route('/unauthorized')
def unauthorized():
    """Unauthorized access page"""
    return render_template('unauthorized.html')
