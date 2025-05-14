"""
Incident analysis utilities for providing actionable insights during incident response.
This module provides functions to analyze incidents and suggest response actions.
"""

import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)

def analyze_phishing_indicators(description):
    """
    Analyze a phishing incident description for key indicators and provide guidance.
    
    Args:
        description: Incident description text
        
    Returns:
        Dictionary with analysis results and recommendations
    """
    indicators = {
        'urls': [],
        'domains': [],
        'sender_emails': [],
        'subject_lines': [],
        'attachments': []
    }
    
    # Extract URLs using a simple regex
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
    indicators['urls'] = re.findall(url_pattern, description)
    
    # Extract potential domains from URLs
    domain_pattern = r'(?:https?://)?(?:www\.)?([^/\s<>"\']+\.[^/\s<>"\']+)'
    domain_matches = re.findall(domain_pattern, description)
    indicators['domains'] = list(set(domain_matches))  # Remove duplicates
    
    # Look for email addresses
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    indicators['sender_emails'] = re.findall(email_pattern, description)
    
    # Look for common file attachment extensions
    attachment_pattern = r'[^\s<>"\']+\.(?:pdf|doc|docx|xls|xlsx|zip|rar|exe|js|vbs)'
    indicators['attachments'] = re.findall(attachment_pattern, description)
    
    # Extract likely subject lines (text in quotes or after "Subject:" keyword)
    # First look for "Subject:" followed by text
    subject_prefix_pattern = r'Subject:\s*([^\n"]+)'
    subject_matches = re.findall(subject_prefix_pattern, description)
    for match in subject_matches:
        if match and len(match) > 3:
            indicators['subject_lines'].append(match)
            
    # Then look for text in double quotes that might be subject lines
    quoted_text_pattern = r'"([^"]+)"'
    quoted_matches = re.findall(quoted_text_pattern, description)
    for match in quoted_matches:
        if match and len(match) > 3:
            indicators['subject_lines'].append(match)
    
    # Generate recommendations based on findings
    recommendations = []
    
    if indicators['urls'] or indicators['domains']:
        recommendations.append("Block identified malicious URLs and domains at the email gateway and web proxy")
        recommendations.append("Scan your network for other emails from the same sender or containing the same URLs")
    
    if indicators['sender_emails']:
        recommendations.append("Block the sender email addresses at the email gateway")
        recommendations.append("Review email logs to identify other recipients who received similar emails")
    
    if indicators['attachments']:
        recommendations.append("Scan the attachments in a sandbox environment to determine malicious behavior")
        recommendations.append("Block attachment types at email gateway and check for other instances of these files")
    
    return {
        'indicators': indicators,
        'recommendations': recommendations
    }

def analyze_malware_indicators(description):
    """
    Analyze a malware incident description for key indicators and provide guidance.
    
    Args:
        description: Incident description text
        
    Returns:
        Dictionary with analysis results and recommendations
    """
    indicators = {
        'file_hashes': [],
        'file_names': [],
        'ip_addresses': [],
        'registry_keys': [],
        'processes': []
    }
    
    # Extract potential file hashes
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    
    indicators['file_hashes'] = (
        re.findall(md5_pattern, description) +
        re.findall(sha1_pattern, description) +
        re.findall(sha256_pattern, description)
    )
    
    # Extract filenames with extensions
    filename_pattern = r'\b\w+\.(exe|dll|sys|bat|ps1|vbs|js|jar|tmp)\b'
    indicators['file_names'] = re.findall(filename_pattern, description)
    
    # Extract IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    indicators['ip_addresses'] = re.findall(ip_pattern, description)
    
    # Extract Windows registry keys
    registry_pattern = r'HKEY_[A-Z_]+\\[^\s]+'
    indicators['registry_keys'] = re.findall(registry_pattern, description)
    
    # Extract process names
    process_pattern = r'\b\w+\.exe\b'
    indicators['processes'] = re.findall(process_pattern, description)
    
    # Generate recommendations
    recommendations = []
    
    if indicators['file_hashes'] or indicators['file_names']:
        recommendations.append("Create signature-based detections for the identified files")
        recommendations.append("Scan all systems using the file hash IOCs to identify other infected machines")
    
    if indicators['ip_addresses']:
        recommendations.append("Block malicious IP addresses at the firewall and monitor for any connection attempts")
        recommendations.append("Search network logs for historical connections to these IPs to identify additional compromised hosts")
    
    if indicators['processes']:
        recommendations.append("Create process-based monitoring rules to detect the malware execution")
        recommendations.append("Use EDR tools to hunt for these processes across your environment")
    
    if indicators['registry_keys']:
        recommendations.append("Check registry keys on infected and suspected systems")
        recommendations.append("Create detection rules for registry modifications")
    
    return {
        'indicators': indicators,
        'recommendations': recommendations
    }

def analyze_data_breach_indicators(description):
    """
    Analyze a data breach incident description and provide guidance.
    
    Args:
        description: Incident description text
        
    Returns:
        Dictionary with analysis results and recommendations
    """
    indicators = {
        'data_types': [],
        'access_vectors': [],
        'affected_systems': [],
        'exfiltration_methods': []
    }
    
    # Data types potentially exposed
    data_types = [
        'PII', 'personal identifiable information',
        'SSN', 'social security', 
        'credit card', 'payment card', 
        'health record', 'PHI', 
        'password', 'credential',
        'financial', 'banking',
        'intellectual property', 'trade secret'
    ]
    
    # Access vectors
    access_vectors = [
        'phishing', 'spear-phishing',
        'vulnerability', 'exploit', 'CVE',
        'credential', 'password',
        'brute force', 'dictionary attack',
        'insider', 'privileged access',
        'third-party', 'vendor', 'supply chain'
    ]
    
    # Systems commonly affected
    systems = [
        'database', 'SQL', 'MongoDB', 'Oracle',
        'file server', 'cloud storage', 'S3', 'Azure',
        'email', 'Exchange', 'Office 365',
        'web server', 'application server',
        'CRM', 'ERP', 'HR system', 'finance system'
    ]
    
    # Exfiltration methods
    exfil_methods = [
        'FTP', 'SFTP', 
        'email attachment', 'email forwarding',
        'cloud storage', 'Dropbox', 'Google Drive',
        'web upload', 'HTTP POST',
        'DNS tunneling', 'C2', 'command and control',
        'encrypted channel', 'TLS', 'SSL',
        'physical', 'USB', 'hard drive', 'print'
    ]
    
    # Find matches in the description
    for data_type in data_types:
        if re.search(r'\b' + re.escape(data_type.lower()) + r'\b', description.lower()):
            indicators['data_types'].append(data_type)
    
    for vector in access_vectors:
        if re.search(r'\b' + re.escape(vector.lower()) + r'\b', description.lower()):
            indicators['access_vectors'].append(vector)
    
    for system in systems:
        if re.search(r'\b' + re.escape(system.lower()) + r'\b', description.lower()):
            indicators['affected_systems'].append(system)
    
    for method in exfil_methods:
        if re.search(r'\b' + re.escape(method.lower()) + r'\b', description.lower()):
            indicators['exfiltration_methods'].append(method)
    
    # Generate recommendations
    recommendations = []
    
    # Generic recommendations for all data breaches
    recommendations.append("Immediately contain the breach by isolating affected systems")
    recommendations.append("Preserve forensic evidence for investigation and potential legal proceedings")
    
    # Specific recommendations based on indicators
    if indicators['data_types']:
        sensitive_data = True if any(x in ['PII', 'SSN', 'credit card', 'PHI', 'health record'] for x in indicators['data_types']) else False
        if sensitive_data:
            recommendations.append("Prepare for notification requirements under applicable regulations (GDPR, HIPAA, state laws)")
            recommendations.append("Engage legal counsel and consider bringing in a third-party forensics team")
    
    if indicators['access_vectors']:
        if any(x in ['phishing', 'spear-phishing'] for x in indicators['access_vectors']):
            recommendations.append("Conduct organization-wide password resets and implement MFA if not already in place")
        if any(x in ['vulnerability', 'exploit', 'CVE'] for x in indicators['access_vectors']):
            recommendations.append("Patch the exploited vulnerability and scan for similar vulnerabilities")
        if any(x in ['insider', 'privileged'] for x in indicators['access_vectors']):
            recommendations.append("Review access controls and implement least privilege principles")
    
    if indicators['affected_systems']:
        if any(x in ['database', 'SQL', 'MongoDB', 'Oracle'] for x in indicators['affected_systems']):
            recommendations.append("Audit database access logs and implement data loss prevention controls")
        if any(x in ['cloud', 'S3', 'Azure'] for x in indicators['affected_systems']):
            recommendations.append("Review cloud security configurations and enable advanced monitoring")
    
    return {
        'indicators': indicators,
        'recommendations': recommendations
    }

def generate_incident_summary(incident, responses):
    """
    Generate a comprehensive summary of an incident and its response status.
    
    Args:
        incident: The Incident object
        responses: List of IncidentResponse objects
    
    Returns:
        Dictionary with summary information
    """
    # Calculate statistics
    total_steps = len(responses)
    completed_steps = sum(1 for r in responses if r.completed)
    completion_percentage = (completed_steps / total_steps * 100) if total_steps > 0 else 0
    
    time_elapsed = datetime.utcnow() - incident.created_at
    days_elapsed = time_elapsed.days
    hours_elapsed = time_elapsed.seconds // 3600
    
    # Determine criticality
    severity_weights = {
        'Low': 1,
        'Medium': 2,
        'High': 3,
        'Critical': 4
    }
    
    severity_score = severity_weights.get(incident.severity, 2)
    status_weight = 1 if incident.status == 'Resolved' else 2
    time_weight = min(days_elapsed // 2 + 1, 5)  # Cap at 5
    
    criticality = (severity_score * status_weight * time_weight) // 2
    criticality_level = 'Low'
    if criticality > 10:
        criticality_level = 'Critical'
    elif criticality > 6:
        criticality_level = 'High'
    elif criticality > 3:
        criticality_level = 'Medium'
    
    # Analyze based on incident type
    incident_analysis = {}
    if incident.description:
        if incident.incident_type == 'Phishing':
            incident_analysis = analyze_phishing_indicators(incident.description)
        elif incident.incident_type == 'Malware':
            incident_analysis = analyze_malware_indicators(incident.description)
        elif incident.incident_type == 'Data Breach':
            incident_analysis = analyze_data_breach_indicators(incident.description)
    
    # Generate next steps
    next_steps = []
    if completion_percentage < 100:
        for response in responses:
            if not response.completed:
                next_steps.append(response.action)
                if len(next_steps) >= 3:  # Limit to top 3 pending steps
                    break
    else:
        if incident.status != 'Closed':
            next_steps.append("Document lessons learned")
            next_steps.append("Conduct post-incident review")
            next_steps.append("Update incident response plan based on findings")
    
    return {
        'id': incident.id,
        'title': incident.title,
        'type': incident.incident_type,
        'severity': incident.severity,
        'status': incident.status,
        'created_at': incident.created_at.isoformat(),
        'time_elapsed': f"{days_elapsed} days, {hours_elapsed} hours",
        'completion': {
            'completed_steps': completed_steps,
            'total_steps': total_steps,
            'percentage': round(completion_percentage, 1)
        },
        'criticality': {
            'level': criticality_level,
            'score': criticality
        },
        'analysis': incident_analysis,
        'next_steps': next_steps
    }