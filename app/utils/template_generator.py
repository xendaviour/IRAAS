"""
Template generator for security incident response templates.
This module provides utility functions to create predefined templates for common security incidents.
"""

from app import db
from app.models import IncidentTemplate, TemplateStep

def create_template_if_not_exists(name, description, incident_type, steps):
    """
    Create a template if it doesn't already exist in the database.
    
    Args:
        name: The name of the template
        description: Description of the template
        incident_type: Type of incident (e.g., 'Phishing', 'Malware', 'Data Breach')
        steps: List of dictionaries with step_number, action, and description
        
    Returns:
        The created template or the existing one if it already exists
    """
    # Check if template already exists
    template = IncidentTemplate.query.filter_by(name=name).first()
    
    if template:
        return template
        
    # Create new template
    template = IncidentTemplate(
        name=name,
        description=description,
        incident_type=incident_type
    )
    
    db.session.add(template)
    db.session.flush()  # Get template ID without committing
    
    # Add steps
    for step in steps:
        template_step = TemplateStep(
            step_number=step['step_number'],
            action=step['action'],
            description=step.get('description', ''),
            template_id=template.id
        )
        db.session.add(template_step)
    
    db.session.commit()
    return template

def create_phishing_template():
    """Create a template for phishing incident response."""
    steps = [
        {
            'step_number': 1,
            'action': 'Isolate the affected system',
            'description': 'Disconnect the system from the network to prevent further impact.'
        },
        {
            'step_number': 2,
            'action': 'Preserve evidence',
            'description': 'Take screenshots of the phishing email/message and save email headers.'
        },
        {
            'step_number': 3,
            'action': 'Report to IT security team',
            'description': 'Notify the security team with all collected evidence.'
        },
        {
            'step_number': 4,
            'action': 'Change compromised credentials',
            'description': 'Reset passwords for any potentially exposed accounts.'
        },
        {
            'step_number': 5,
            'action': 'Scan for malware',
            'description': 'Run a full system scan to detect any malware that might have been installed.'
        },
        {
            'step_number': 6,
            'action': 'Report to appropriate authorities',
            'description': 'Report the phishing attempt to relevant authorities (e.g., FBI, CISA).'
        },
        {
            'step_number': 7,
            'action': 'Educate users',
            'description': 'Provide training and awareness to prevent future incidents.'
        }
    ]
    
    return create_template_if_not_exists(
        name='Phishing Response',
        description='Standard response protocol for phishing attacks.',
        incident_type='Phishing',
        steps=steps
    )

def create_malware_template():
    """Create a template for malware incident response."""
    steps = [
        {
            'step_number': 1,
            'action': 'Isolate infected systems',
            'description': 'Disconnect affected systems from the network to prevent lateral movement.'
        },
        {
            'step_number': 2,
            'action': 'Identify malware type and indicators of compromise (IOCs)',
            'description': 'Determine the malware type and collect IOCs such as file hashes, IP addresses, and domains.'
        },
        {
            'step_number': 3,
            'action': 'Scan other systems for infection',
            'description': 'Use IOCs to scan other systems for signs of compromise.'
        },
        {
            'step_number': 4,
            'action': 'Remove malware',
            'description': 'Use appropriate tools to remove the malware from affected systems.'
        },
        {
            'step_number': 5,
            'action': 'Restore from clean backups if needed',
            'description': 'If systems are severely compromised, restore from known clean backups.'
        },
        {
            'step_number': 6,
            'action': 'Patch vulnerabilities',
            'description': 'Apply necessary patches to prevent reinfection.'
        },
        {
            'step_number': 7,
            'action': 'Update security measures',
            'description': 'Update antivirus signatures, firewall rules, and other security controls.'
        },
        {
            'step_number': 8,
            'action': 'Document incident and response',
            'description': 'Document the entire incident and response for future reference.'
        }
    ]
    
    return create_template_if_not_exists(
        name='Malware Response',
        description='Standard response protocol for malware infections.',
        incident_type='Malware',
        steps=steps
    )

def create_data_breach_template():
    """Create a template for data breach incident response."""
    steps = [
        {
            'step_number': 1,
            'action': 'Contain the breach',
            'description': 'Isolate affected systems and stop data exfiltration.'
        },
        {
            'step_number': 2,
            'action': 'Assemble response team',
            'description': 'Gather security team, legal, PR, and executive stakeholders.'
        },
        {
            'step_number': 3,
            'action': 'Identify scope and data exposed',
            'description': 'Determine what data was compromised and the extent of the breach.'
        },
        {
            'step_number': 4,
            'action': 'Collect and preserve evidence',
            'description': 'Gather logs, network captures, and other forensic data.'
        },
        {
            'step_number': 5,
            'action': 'Identify attack vector',
            'description': 'Determine how the breach occurred to address vulnerabilities.'
        },
        {
            'step_number': 6,
            'action': 'Notify affected parties',
            'description': 'Inform individuals whose data was compromised in accordance with regulations.'
        },
        {
            'step_number': 7,
            'action': 'Report to authorities',
            'description': 'Notify law enforcement and regulatory bodies as required by law.'
        },
        {
            'step_number': 8,
            'action': 'Remediate vulnerabilities',
            'description': 'Fix security weaknesses that allowed the breach.'
        },
        {
            'step_number': 9,
            'action': 'Enhance monitoring',
            'description': 'Increase security monitoring to detect further unauthorized access.'
        },
        {
            'step_number': 10,
            'action': 'Conduct post-incident review',
            'description': 'Analyze the incident response process and identify improvements.'
        }
    ]
    
    return create_template_if_not_exists(
        name='Data Breach Response',
        description='Comprehensive response protocol for data breach incidents.',
        incident_type='Data Breach',
        steps=steps
    )

def create_ddos_template():
    """Create a template for DDoS attack incident response."""
    steps = [
        {
            'step_number': 1,
            'action': 'Confirm the attack',
            'description': 'Verify that symptoms are consistent with a DDoS attack rather than a system issue.'
        },
        {
            'step_number': 2,
            'action': 'Activate DDoS response team',
            'description': 'Notify relevant team members and external service providers if applicable.'
        },
        {
            'step_number': 3,
            'action': 'Implement traffic filtering',
            'description': 'Apply ACLs, rate limiting, or other filtering to block attack traffic.'
        },
        {
            'step_number': 4,
            'action': 'Scale resources if possible',
            'description': 'Increase capacity to absorb attack traffic if using cloud services.'
        },
        {
            'step_number': 5,
            'action': 'Contact ISP or DDoS mitigation service',
            'description': 'Engage with upstream providers for additional traffic scrubbing.'
        },
        {
            'step_number': 6,
            'action': 'Implement backup connectivity',
            'description': 'Activate redundant connections if primary links are saturated.'
        },
        {
            'step_number': 7,
            'action': 'Monitor attack patterns',
            'description': 'Analyze traffic to identify attack signatures and adjust defenses.'
        },
        {
            'step_number': 8,
            'action': 'Preserve evidence',
            'description': 'Collect logs and traffic samples for later analysis and potential legal action.'
        },
        {
            'step_number': 9,
            'action': 'Communicate with stakeholders',
            'description': 'Keep management, customers, and partners informed about the situation.'
        },
        {
            'step_number': 10,
            'action': 'Post-attack analysis',
            'description': 'Review the attack and response to improve future defenses.'
        }
    ]
    
    return create_template_if_not_exists(
        name='DDoS Attack Response',
        description='Response protocol for Distributed Denial of Service attacks.',
        incident_type='DDoS',
        steps=steps
    )

def create_ransomware_template():
    """Create a template for ransomware incident response."""
    steps = [
        {
            'step_number': 1,
            'action': 'Isolate affected systems',
            'description': 'Disconnect infected systems from the network immediately to prevent spread.'
        },
        {
            'step_number': 2,
            'action': 'Identify ransomware variant',
            'description': 'Determine the specific type of ransomware to guide response actions.'
        },
        {
            'step_number': 3,
            'action': 'Assess scope of encryption',
            'description': 'Determine which systems and data have been encrypted.'
        },
        {
            'step_number': 4,
            'action': 'Preserve ransom note and encrypted files',
            'description': 'Save copies for investigation and potential decryption.'
        },
        {
            'step_number': 5,
            'action': 'Check for data exfiltration',
            'description': 'Modern ransomware often steals data before encryption; investigate for signs of exfiltration.'
        },
        {
            'step_number': 6,
            'action': 'Identify infection vector',
            'description': 'Determine how the ransomware entered the environment.'
        },
        {
            'step_number': 7,
            'action': 'Report to law enforcement',
            'description': 'Notify FBI, CISA, or other appropriate authorities.'
        },
        {
            'step_number': 8,
            'action': 'Evaluate recovery options',
            'description': 'Assess backup availability and integrity for restoration.'
        },
        {
            'step_number': 9,
            'action': 'Restore from clean backups',
            'description': 'Rebuild systems and restore data from verified clean backups.'
        },
        {
            'step_number': 10,
            'action': 'Remediate vulnerabilities',
            'description': 'Address security gaps that allowed the ransomware infection.'
        },
        {
            'step_number': 11,
            'action': 'Conduct business impact analysis',
            'description': 'Assess operational, financial, and reputational impacts.'
        },
        {
            'step_number': 12,
            'action': 'Update incident response plan',
            'description': 'Incorporate lessons learned to improve future response.'
        }
    ]
    
    return create_template_if_not_exists(
        name='Ransomware Response',
        description='Comprehensive response protocol for ransomware attacks.',
        incident_type='Ransomware',
        steps=steps
    )

def create_insider_threat_template():
    """Create a template for insider threat incident response."""
    steps = [
        {
            'step_number': 1,
            'action': 'Assemble response team',
            'description': 'Include HR, legal, security, and management representatives.'
        },
        {
            'step_number': 2,
            'action': 'Preserve evidence',
            'description': 'Collect and secure all relevant digital and physical evidence.'
        },
        {
            'step_number': 3,
            'action': 'Monitor suspect activity',
            'description': 'Implement enhanced monitoring of the suspected insider\'s activities.'
        },
        {
            'step_number': 4,
            'action': 'Revoke access if necessary',
            'description': 'Remove access to sensitive systems and data if risk is imminent.'
        },
        {
            'step_number': 5,
            'action': 'Document unauthorized actions',
            'description': 'Record all suspicious or unauthorized activities with timestamps.'
        },
        {
            'step_number': 6,
            'action': 'Assess data exposure',
            'description': 'Determine what information may have been accessed or exfiltrated.'
        },
        {
            'step_number': 7,
            'action': 'Conduct forensic investigation',
            'description': 'Perform detailed forensic analysis of affected systems.'
        },
        {
            'step_number': 8,
            'action': 'Interview relevant personnel',
            'description': 'Gather information from colleagues and supervisors.'
        },
        {
            'step_number': 9,
            'action': 'Engage legal counsel',
            'description': 'Consult with legal team regarding proper handling and potential action.'
        },
        {
            'step_number': 10,
            'action': 'Take appropriate disciplinary action',
            'description': 'Follow HR policies and legal requirements for addressing the insider threat.'
        },
        {
            'step_number': 11,
            'action': 'Implement corrective measures',
            'description': 'Address security gaps and process weaknesses that enabled the threat.'
        },
        {
            'step_number': 12,
            'action': 'Update security controls',
            'description': 'Enhance monitoring, access controls, and other security measures.'
        }
    ]
    
    return create_template_if_not_exists(
        name='Insider Threat Response',
        description='Protocol for responding to malicious insider activities.',
        incident_type='Insider Threat',
        steps=steps
    )

def create_all_templates():
    """Create all predefined incident response templates."""
    templates = []
    
    templates.append(create_phishing_template())
    templates.append(create_malware_template())
    templates.append(create_data_breach_template())
    templates.append(create_ddos_template())
    templates.append(create_ransomware_template())
    templates.append(create_insider_threat_template())
    
    return templates