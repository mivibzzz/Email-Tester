#!/usr/bin/env python3
"""
Enhanced Email Validation Backend
A Flask web server that provides real email validation services
"""

import re
import dns.resolver
import smtplib
import random
import string
import time
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import threading
import queue

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app setup
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication

# --- Configuration ---
WEBMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'live.com', 'icloud.com', 'aol.com', 'msn.com', 'protonmail.com',
    'yandex.com', 'mail.com', 'zoho.com', 'fastmail.com', 'tutanota.com'
}

ROLE_PREFIXES = {
    'info', 'admin', 'support', 'sales', 'contact', 'help',
    'service', 'team', 'no-reply', 'noreply', 'webmaster',
    'marketing', 'billing', 'accounts', 'hr', 'legal', 'abuse',
    'postmaster', 'security', 'careers', 'jobs'
}

DISPOSABLE_DOMAINS = {
    'mailinator.com', '10minutemail.com', 'tempmail.com', 'trashmail.com',
    'guerrillamail.com', 'maildrop.cc', 'temp-mail.org', 'throwaway.email',
    'getnada.com', 'mailcatch.com', 'sharklasers.com', 'yopmail.com',
    'mailnesia.com', 'emailondeck.com', 'spamgourmet.com', 'mytrashmail.com'
}

# Global validation state
validation_sessions = {}

# --- Enhanced Validation Functions ---

def is_valid_syntax(email):
    """Check if email has valid syntax"""
    if not email or '@' not in email:
        return False
    
    # More comprehensive regex pattern
    pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    
    if not re.match(pattern, email):
        return False
    
    # Additional checks
    local, domain = email.rsplit('@', 1)
    
    # Local part should not exceed 64 characters
    if len(local) > 64:
        return False
    
    # Domain should not exceed 253 characters
    if len(domain) > 253:
        return False
    
    # Domain should have at least one dot
    if '.' not in domain:
        return False
    
    return True

def get_domain(email):
    """Extract domain from email"""
    try:
        return email.split('@')[-1].lower()
    except:
        return ''

def has_mx_record(domain):
    """Check if domain has MX records"""
    try:
        # Set timeout for DNS queries
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        
        answers = resolver.resolve(domain, 'MX')
        return bool(answers)
    except dns.resolver.NXDOMAIN:
        logger.info(f"Domain {domain} does not exist")
        return False
    except dns.resolver.NoAnswer:
        logger.info(f"Domain {domain} has no MX records")
        return False
    except dns.resolver.Timeout:
        logger.warning(f"DNS timeout for domain {domain}")
        return False
    except Exception as e:
        logger.error(f"DNS error for domain {domain}: {str(e)}")
        return False

def is_disposable(domain):
    """Check if domain is a known disposable email provider"""
    return domain in DISPOSABLE_DOMAINS

def is_role_based(local):
    """Check if local part indicates a role-based email"""
    return local.lower() in ROLE_PREFIXES

def get_mx_server(domain):
    """Get the primary MX server for a domain"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        
        answers = resolver.resolve(domain, 'MX')
        # Sort by preference (lower number = higher preference)
        mx_records = sorted([(record.preference, str(record.exchange).rstrip('.')) 
                           for record in answers])
        return mx_records[0][1] if mx_records else None
    except Exception as e:
        logger.error(f"Error getting MX server for {domain}: {str(e)}")
        return None

def smtp_verify(email, timeout=10):
    """
    Verify email using SMTP RCPT TO command
    Returns True if valid, False if invalid, None if couldn't determine
    """
    domain = get_domain(email)
    
    try:
        mx_server = get_mx_server(domain)
        if not mx_server:
            return False
        
        logger.info(f"Connecting to MX server {mx_server} for {email}")
        
        # Connect to SMTP server
        server = smtplib.SMTP(timeout=timeout)
        server.set_debuglevel(0)  # Disable debug output
        
        # Connect to MX server
        server.connect(mx_server, 25)
        
        # SMTP conversation
        server.helo('emailvalidator.local')  # Be polite
        server.mail('test@emailvalidator.local')  # Sender
        
        # The crucial test - RCPT TO
        code, response = server.rcpt(email)
        server.quit()
        
        # Success codes: 250 (OK) and 251 (User not local; will forward)
        is_valid = code in (250, 251)
        logger.info(f"SMTP verification for {email}: {code} - {'Valid' if is_valid else 'Invalid'}")
        
        return is_valid
        
    except smtplib.SMTPRecipientsRefused:
        logger.info(f"SMTP verification for {email}: Recipient refused")
        return False
    except smtplib.SMTPServerDisconnected:
        logger.warning(f"SMTP server disconnected for {email}")
        return None
    except smtplib.SMTPConnectError:
        logger.warning(f"Could not connect to SMTP server for {email}")
        return None
    except Exception as e:
        logger.error(f"SMTP error for {email}: {str(e)}")
        return None

def is_catch_all(domain):
    """Check if domain has catch-all email setup"""
    try:
        # Generate a random email that shouldn't exist
        fake_local = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
        fake_email = f"{fake_local}@{domain}"
        
        # If this validates, the domain likely has catch-all
        result = smtp_verify(fake_email, timeout=5)
        return result is True
        
    except Exception as e:
        logger.error(f"Catch-all check error for {domain}: {str(e)}")
        return False

def calculate_score(result):
    """Calculate overall email score based on validation results"""
    score = 0
    
    # Syntax (20 points)
    score += 20 if result['syntax'] else 0
    
    # MX Record (20 points)
    score += 20 if result['mx'] else 0
    
    # Not disposable (10 points)
    score += 0 if result['disposable'] else 10
    
    # Not role-based (10 points)
    score += 0 if result['role'] else 10
    
    # Not catch-all (10 points)
    score += 0 if result['catch_all'] else 10
    
    # SMTP verification (30 points)
    if result['smtp'] is True:
        score += 30
    elif result['smtp'] is False:
        score += 0
    else:
        # Assume OK if skipped (e.g., for webmail)
        score += 25
    
    return min(100, score)

def determine_status(score):
    """Determine status based on score"""
    if score >= 90:
        return 'Excellent'
    elif score >= 75:
        return 'Good'
    elif score >= 60:
        return 'Fair'
    elif score >= 40:
        return 'Poor'
    else:
        return 'Invalid'

def validate_single_email(email, config):
    """Validate a single email address"""
    result = {
        'email': email.strip(),
        'syntax': False,
        'domain': '',
        'mx': False,
        'disposable': False,
        'role': False,
        'catch_all': False,
        'smtp': None,
        'score': 0,
        'status': 'Invalid',
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        # Syntax validation
        result['syntax'] = is_valid_syntax(email)
        if not result['syntax']:
            result['score'] = 0
            return result
        
        # Extract domain
        local, domain = email.rsplit('@', 1)
        result['domain'] = domain.lower()
        
        # MX Record check
        result['mx'] = has_mx_record(domain)
        
        # Disposable domain check
        result['disposable'] = is_disposable(domain)
        
        # Role-based check
        result['role'] = is_role_based(local)
        
        # Catch-all check (only if domain has MX)
        if result['mx'] and config.get('check_catch_all', True):
            result['catch_all'] = is_catch_all(domain)
        
        # SMTP verification
        skip_smtp = config.get('skip_smtp', 'webmail')
        timeout = config.get('smtp_timeout', 10)
        
        should_skip = (
            skip_smtp == 'all' or 
            (skip_smtp == 'webmail' and domain in WEBMAIL_DOMAINS) or
            not result['mx']
        )
        
        if not should_skip:
            result['smtp'] = smtp_verify(email, timeout)
        
        # Calculate final score and status
        result['score'] = calculate_score(result)
        result['status'] = determine_status(result['score'])
        
    except Exception as e:
        logger.error(f"Error validating {email}: {str(e)}")
        result['error'] = str(e)
    
    return result

# --- API Routes ---

@app.route('/')
def index():
    """Serve the main dashboard"""
    # Read the HTML file and serve it
    try:
        with open('email_validator_dashboard.html', 'r') as f:
            html_content = f.read()
        return html_content
    except FileNotFoundError:
        # If file doesn't exist, return a simple redirect message
        return """
        <html>
        <body>
            <h1>Email Validator Backend</h1>
            <p>Backend server is running! Please serve the HTML dashboard separately or place the HTML file in the same directory.</p>
            <p>API endpoints available:</p>
            <ul>
                <li>POST /api/validate - Start email validation</li>
                <li>GET /api/status/&lt;session_id&gt; - Check validation status</li>
                <li>GET /api/results/&lt;session_id&gt; - Get validation results</li>
            </ul>
        </body>
        </html>
        """

@app.route('/api/validate', methods=['POST'])
def start_validation():
    """Start email validation process"""
    try:
        data = request.get_json()
        emails = data.get('emails', [])
        config = data.get('config', {})
        
        if not emails:
            return jsonify({'error': 'No emails provided'}), 400
        
        # Generate session ID
        session_id = f"session_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # Initialize session
        validation_sessions[session_id] = {
            'status': 'processing',
            'total': len(emails),
            'completed': 0,
            'results': [],
            'config': config,
            'started_at': datetime.now().isoformat()
        }
        
        # Start validation in background thread
        thread = threading.Thread(
            target=process_validation,
            args=(session_id, emails, config)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'session_id': session_id,
            'status': 'started',
            'total_emails': len(emails)
        })
        
    except Exception as e:
        logger.error(f"Error starting validation: {str(e)}")
        return jsonify({'error': str(e)}), 500

def process_validation(session_id, emails, config):
    """Process email validation in background"""
    session = validation_sessions[session_id]
    delay = config.get('delay', 1.0)
    
    try:
        for i, email in enumerate(emails):
            if email.strip():  # Skip empty emails
                result = validate_single_email(email.strip(), config)
                session['results'].append(result)
            
            session['completed'] = i + 1
            
            # Add delay between validations (except for the last one)
            if i < len(emails) - 1 and delay > 0:
                time.sleep(delay)
        
        session['status'] = 'completed'
        session['completed_at'] = datetime.now().isoformat()
        
    except Exception as e:
        logger.error(f"Error in validation process: {str(e)}")
        session['status'] = 'error'
        session['error'] = str(e)

@app.route('/api/status/<session_id>')
def get_status(session_id):
    """Get validation status"""
    if session_id not in validation_sessions:
        return jsonify({'error': 'Session not found'}), 404
    
    session = validation_sessions[session_id]
    return jsonify({
        'status': session['status'],
        'total': session['total'],
        'completed': session['completed'],
        'progress': (session['completed'] / session['total']) * 100 if session['total'] > 0 else 0
    })

@app.route('/api/results/<session_id>')
def get_results(session_id):
    """Get validation results"""
    if session_id not in validation_sessions:
        return jsonify({'error': 'Session not found'}), 404
    
    session = validation_sessions[session_id]
    
    if session['status'] != 'completed':
        return jsonify({'error': 'Validation not completed'}), 400
    
    # Calculate statistics
    results = session['results']
    total = len(results)
    
    if total == 0:
        return jsonify({'results': [], 'stats': {}})
    
    scores = [r['score'] for r in results if 'score' in r]
    avg_score = sum(scores) / len(scores) if scores else 0
    
    stats = {
        'total': total,
        'average_score': round(avg_score, 1),
        'excellent': len([r for r in results if r.get('score', 0) >= 90]),
        'good': len([r for r in results if 75 <= r.get('score', 0) < 90]),
        'fair': len([r for r in results if 60 <= r.get('score', 0) < 75]),
        'poor': len([r for r in results if 40 <= r.get('score', 0) < 60]),
        'invalid': len([r for r in results if r.get('score', 0) < 40])
    }
    
    return jsonify({
        'results': results,
        'stats': stats,
        'session_info': {
            'started_at': session['started_at'],
            'completed_at': session.get('completed_at'),
            'config': session['config']
        }
    })

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_sessions': len(validation_sessions)
    })

# --- Cleanup old sessions ---
def cleanup_old_sessions():
    """Clean up sessions older than 1 hour"""
    current_time = time.time()
    to_remove = []
    
    for session_id, session in validation_sessions.items():
        started_timestamp = datetime.fromisoformat(session['started_at']).timestamp()
        if current_time - started_timestamp > 3600:  # 1 hour
            to_remove.append(session_id)
    
    for session_id in to_remove:
        del validation_sessions[session_id]
        logger.info(f"Cleaned up old session: {session_id}")

# Schedule cleanup every 30 minutes
def schedule_cleanup():
    while True:
        time.sleep(1800)  # 30 minutes
        cleanup_old_sessions()

# --- Main ---
if __name__ == '__main__':
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=schedule_cleanup)
    cleanup_thread.daemon = True
    cleanup_thread.start()
    
    print("🚀 Email Validator Backend Server Starting...")
    print("📧 Dashboard available at: http://localhost:5000")
    print("🔧 API endpoints:")
    print("   POST /api/validate - Start validation")
    print("   GET /api/status/<session_id> - Check status")
    print("   GET /api/results/<session_id> - Get results")
    print("   GET /api/health - Health check")
    
    # Run Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,  # Set to True for development
        threaded=True
    )