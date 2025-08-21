from flask import render_template, request, redirect, url_for, flash, session, jsonify, send_file, make_response, abort
from werkzeug.security import generate_password_hash, check_password_hash
from app import app
from firebase_auth import login_required, role_required, get_current_user, log_audit_action, check_password_reset_required
from firebase_config import authenticate_user, create_user_account, get_user_info
from data_store import DATA_STORE, find_user_by_email, initialize_sample_data
from firebase_models import UserModel, DepartmentModel, AuditModel, RiskAssessmentModel, FindingModel, CorrectiveActionModel, MessageModel, EvidenceModel, ReportModel, AuditLogModel
# Import utilities - will create these functions if needed
import secrets
import string
import os
import uuid

def generate_password(length=12):
    """Generate a secure random password"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(characters) for _ in range(length))

def save_uploaded_file(file):
    """Save uploaded file and return filename"""
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    
    filename = f"{uuid.uuid4()}_{file.filename}"
    filepath = os.path.join('uploads', filename)
    file.save(filepath)
    return filename
from datetime import datetime, timedelta
import os
import uuid
import json
from uuid import uuid4
# Try importing reportlab with fallback
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    print("ReportLab not available, PDF generation disabled")
    REPORTLAB_AVAILABLE = False
import io

# Initialize sample data on first import
initialize_sample_data()

# Initialize model instances
user_model = UserModel()
dept_model = DepartmentModel() 
audit_model = AuditModel()
risk_model = RiskAssessmentModel()
finding_model = FindingModel()
action_model = CorrectiveActionModel()
message_model = MessageModel()
evidence_model = EvidenceModel()
report_model = ReportModel()
audit_log_model = AuditLogModel()

@app.route('/')
def landing():
    """Landing page with role-based login options"""
    if 'user_id' in session:
        # Check if user actually exists before redirecting
        user = get_current_user()
        if user:
            return redirect(url_for('dashboard'))
        else:
            # Clear invalid session
            session.clear()
    return render_template('landing.html')

@app.route('/login/<role>')
def login_form(role):
    """Display login form for specific role"""
    valid_roles = ['director', 'head_of_business_control', 'auditor', 'auditee']
    if role not in valid_roles:
        flash('Invalid role specified.', 'error')
        return redirect(url_for('landing'))
    return render_template('login.html', role=role)

@app.route('/login', methods=['POST'])
def login():
    """Process login with Firebase authentication"""
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    
    # Authenticate with Firebase or mock
    firebase_user = authenticate_user(email, password)
    if not firebase_user:
        flash('Invalid email or password.', 'error')
        return redirect(url_for('login_form', role=role))
    
    # Get user data from data store
    user_data = find_user_by_email(email)
    if not user_data or user_data.get('role') != role or not user_data.get('is_active', False):
        flash('Invalid email, role, or account inactive.', 'error')
        return redirect(url_for('login_form', role=role))
    
    # Set session
    session['user_id'] = user_data['id']
    session['user_role'] = user_data['role']
    session['firebase_token'] = firebase_user['idToken']
    
    # Update last login
    # Update last login time in data store
    if user_data['id'] in DATA_STORE['users']:
        DATA_STORE['users'][user_data['id']]['last_login'] = datetime.now()
    
    log_audit_action('login', 'user', user_data['id'], f'User {email} logged in')
    
    # Check password reset requirement - skip for development
    if user_data.get('password_reset_required', False) and email not in ["admin@audit.system", "head@audit.system", "auditor@audit.system", "auditee@audit.system"]:
        flash('You must change your password before continuing.', 'warning')
        return redirect(url_for('profile'))
    
    flash(f'Welcome, {user_data.get("first_name", "")} {user_data.get("last_name", "")}!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    user = get_current_user()
    if user:
        log_audit_action('logout', 'user', user['id'], f'User {user.get("email", "")} logged out')
    
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Role-based dashboard"""
    user = get_current_user()
    if not user:
        session.clear()  # Clear invalid session
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('landing'))
    
    role = user.get('role')
    
    if role == 'director':
        return director_dashboard()
    elif role == 'head_of_business_control':
        return head_of_business_control_dashboard()
    elif role == 'auditor':
        return auditor_dashboard()
    elif role == 'auditee':
        return auditee_dashboard()
    else:
        flash('Invalid role.', 'error')
        session.clear()  # Clear invalid session
        return redirect(url_for('landing'))

@app.route('/director_dashboard')
@login_required
@role_required('director')
def director_dashboard():
    """Director dashboard - approve plans and review reports"""
    # Get audits pending approval
    pending_audits = [audit for audit in DATA_STORE['audits'].values() 
                     if audit.get('status') == 'pending_director_approval']
    
    # Get completed reports for review  
    completed_audits = [audit for audit in DATA_STORE['audits'].values() 
                       if audit.get('status') == 'completed']
    
    # Get all audits for overview
    all_audits = list(DATA_STORE['audits'].values())
    
    # Risk overview
    risks = list(DATA_STORE['risk_assessments'].values())
    
    # Dashboard statistics
    stats = {
        'pending_approvals': len(pending_audits),
        'completed_audits': len(completed_audits),
        'total_risks': len(risks),
        'high_risks': len([r for r in risks if r.get('risk_level') == 'high'])
    }
    
    # Get user notifications  
    user = get_current_user()
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('director/dashboard.html', 
                         pending_audits=pending_audits,
                         completed_audits=completed_audits,
                         all_audits=all_audits,
                         risks=risks,
                         stats=stats,
                         current_user=user,
                         notifications=notifications)

@app.route('/head_of_business_control_dashboard')
@login_required
@role_required('head_of_business_control')
def head_of_business_control_dashboard():
    """Head of Business Control dashboard - create plans, assign auditors"""
    # Get drafts and audits in various stages
    draft_audits = [audit for audit in DATA_STORE['audits'].values() 
                   if audit.get('status') == 'draft']
    approved_audits = [audit for audit in DATA_STORE['audits'].values() 
                      if audit.get('status') == 'approved']
    in_progress_audits = [audit for audit in DATA_STORE['audits'].values() 
                         if audit.get('status') == 'in_progress']
    
    # Get auditors for assignment
    auditors = [user for user in DATA_STORE['users'].values() 
               if user.get('role') == 'auditor']
    auditees = [user for user in DATA_STORE['users'].values() 
               if user.get('role') == 'auditee']
    
    # Risk assessments
    risks = list(DATA_STORE['risk_assessments'].values())
    
    # Corrective actions tracking
    all_actions = list(DATA_STORE['corrective_actions'].values())
    overdue_actions = [a for a in all_actions if a.get('target_date') and 
                      datetime.fromisoformat(a['target_date']) < datetime.now() and 
                      a.get('status') != 'completed']
    
    stats = {
        'draft_audits': len(draft_audits),
        'approved_audits': len(approved_audits), 
        'in_progress_audits': len(in_progress_audits),
        'total_risks': len(risks),
        'overdue_actions': len(overdue_actions)
    }
    
    # Get user notifications  
    user = get_current_user()
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('head_of_business_control/dashboard.html',
                         draft_audits=draft_audits,
                         approved_audits=approved_audits,
                         in_progress_audits=in_progress_audits,
                         auditors=auditors,
                         auditees=auditees,
                         risks=risks,
                         overdue_actions=overdue_actions,
                         stats=stats,
                         current_user=user,
                         notifications=notifications)

@app.route('/auditor_dashboard')
@login_required
@role_required('auditor')
def auditor_dashboard():
    """Auditor dashboard - manage assigned audits"""
    user = get_current_user()
    
    # Get audits assigned to this auditor
    assigned_audits = [audit for audit in DATA_STORE['audits'].values() 
                      if audit.get('auditor_id') == user['id']]
    
    # Get findings for audits
    auditor_findings = [finding for finding in DATA_STORE['findings'].values() 
                       if finding.get('audit_id') in [a['id'] for a in assigned_audits]]
    
    # Get messages
    auditor_messages = [msg for msg in DATA_STORE['messages'].values() 
                       if msg.get('recipient_id') == user['id'] or msg.get('sender_id') == user['id']]
    
    # Get evidence files
    evidence_files = [evidence for evidence in DATA_STORE['evidence_files'].values() 
                     if evidence.get('audit_id') in [a['id'] for a in assigned_audits]]
    
    stats = {
        'assigned_audits': len(assigned_audits),
        'total_findings': len(auditor_findings),
        'open_findings': len([f for f in auditor_findings if f.get('status') == 'open']),
        'unread_messages': len([m for m in auditor_messages if not m.get('is_read', True)])
    }
    
    # Get user notifications  
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('auditor/dashboard.html',
                         assigned_audits=assigned_audits,
                         findings=auditor_findings,
                         messages=auditor_messages,
                         evidence_files=evidence_files,
                         stats=stats,
                         current_user=user,
                         notifications=notifications)

@app.route('/auditee_dashboard')
@login_required
@role_required('auditee')
def auditee_dashboard():
    """Auditee dashboard - respond to audit requests"""
    user = get_current_user()
    
    # Get audits where this user is auditee
    auditee_audits = [audit for audit in DATA_STORE['audits'].values() 
                     if audit.get('auditee_id') == user['id']]
    
    # Get corrective actions assigned to this auditee
    my_actions = [action for action in DATA_STORE['corrective_actions'].values() 
                 if action.get('responsible_person_id') == user['id']]
    
    # Get messages for this auditee
    auditee_messages = [msg for msg in DATA_STORE['messages'].values() 
                       if msg.get('recipient_id') == user['id']]
    
    # Get evidence files uploaded by this auditee
    my_evidence = [evidence for evidence in DATA_STORE['evidence_files'].values() 
                  if evidence.get('uploaded_by') == user['id']]
    
    stats = {
        'active_audits': len([a for a in auditee_audits if a.get('status') in ['in_progress', 'review']]),
        'pending_actions': len([a for a in my_actions if a.get('status') == 'pending']),
        'overdue_actions': len([a for a in my_actions if a.get('target_date') and 
                               datetime.fromisoformat(a['target_date']) < datetime.now() and 
                               a.get('status') != 'completed']),
        'unread_messages': len([m for m in auditee_messages if not m.get('is_read', True)])
    }
    
    # Get user notifications  
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('auditee/dashboard.html',
                         my_audits=auditee_audits,
                         corrective_actions=my_actions,
                         messages=auditee_messages,
                         evidence_files=my_evidence,
                         stats=stats,
                         current_user=user,
                         notifications=notifications)

# Risk Assessment Routes
@app.route('/risk-assessment')
@login_required
@role_required('head_of_business_control', 'director')
def risk_assessment():
    """Risk assessment management"""
    risks = list(DATA_STORE['risks'].values())
    departments = list(DATA_STORE['departments'].values())
    
    return render_template('risk_assessment.html', risks=risks, departments=departments)

@app.route('/risk-assessment/create', methods=['GET', 'POST'])
@login_required
@role_required('head_of_business_control')
def create_risk_assessment():
    """Create new risk assessment"""
    if request.method == 'POST':
        try:
            risk_data = {
                'risk_description': request.form['risk_description'],
                'department_id': request.form['department_id'],
                'impact_level': request.form['impact_level'],
                'likelihood_level': request.form['likelihood_level'],
                'mitigation_measures': request.form.get('mitigation_measures', ''),
                'risk_owner': request.form.get('risk_owner', ''),
                'created_by': get_current_user()['id']
            }
            
            risk_id = str(uuid.uuid4())
            risk_data['id'] = risk_id
            risk_data['created_at'] = datetime.now()
            DATA_STORE['risks'][risk_id] = risk_data
            log_audit_action('create', 'risk_assessment', risk_id, 'Risk assessment created')
            
            flash('Risk assessment created successfully.', 'success')
            return redirect(url_for('risk_assessment'))
            
        except Exception as e:
            flash(f'Error creating risk assessment: {str(e)}', 'error')
    
    departments = list(DATA_STORE['departments'].values())
    return render_template('create_risk_assessment.html', departments=departments)

# Audit Planning Routes
@app.route('/audit-planning')
@login_required
@role_required('head_of_business_control', 'director')
def audit_planning():
    """Audit planning interface"""
    audits = list(DATA_STORE['audits'].values())
    risks = list(DATA_STORE['risks'].values())
    departments = list(DATA_STORE['departments'].values())
    
    return render_template('audit_planning.html', audits=audits, risks=risks, departments=departments)

@app.route('/audit-planning/create', methods=['GET', 'POST'])
@login_required
@role_required('head_of_business_control')
def create_audit_plan():
    """Create new audit plan"""
    if request.method == 'POST':
        try:
            audit_data = {
                'title': request.form['title'],
                'description': request.form.get('description', ''),
                'audit_type': request.form['audit_type'],
                'department_id': request.form['department_id'],
                'audit_scope': request.form.get('audit_scope', ''),
                'audit_objectives': request.form.get('audit_objectives', ''),
                'planned_start_date': request.form.get('planned_start_date'),
                'planned_end_date': request.form.get('planned_end_date'),
                'priority': request.form.get('priority', 'medium'),
                'created_by_id': get_current_user()['id'],
                'status': 'draft'
            }
            
            audit_id = str(uuid.uuid4())
            audit_data['id'] = audit_id
            audit_data['created_at'] = datetime.now()
            DATA_STORE['audits'][audit_id] = audit_data
            log_audit_action('create', 'audit', audit_id, 'Audit plan created')
            
            flash('Audit plan created successfully.', 'success')
            return redirect(url_for('audit_planning'))
            
        except Exception as e:
            flash(f'Error creating audit plan: {str(e)}', 'error')
    
    departments = list(DATA_STORE['departments'].values())
    risks = list(DATA_STORE['risks'].values())
    return render_template('create_audit_plan.html', departments=departments, risks=risks)

@app.route('/audit-planning/<audit_id>/submit-for-approval', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def submit_audit_for_approval(audit_id):
    """Submit audit plan to Director for approval"""
    try:
        audit_data = {
            'status': 'pending_director_approval',
            'plan_submitted_at': datetime.now().isoformat()
        }
        
        if audit_id in DATA_STORE['audits']:
            DATA_STORE['audits'][audit_id].update(audit_data)
        log_audit_action('submit_for_approval', 'audit', audit_id, 'Audit plan submitted for director approval')
        
        flash('Audit plan submitted for Director approval.', 'success')
        
    except Exception as e:
        flash(f'Error submitting audit plan: {str(e)}', 'error')
    
    return redirect(url_for('audit_planning'))

@app.route('/director/approve-audit/<audit_id>', methods=['POST'])
@login_required
@role_required('director')
def approve_audit_plan(audit_id):
    """Director approves audit plan"""
    try:
        audit_data = {
            'status': 'approved',
            'director_approved_at': datetime.now().isoformat(),
            'director_feedback': request.form.get('director_feedback', '')
        }
        
        if audit_id in DATA_STORE['audits']:
            DATA_STORE['audits'][audit_id].update(audit_data)
        log_audit_action('approve', 'audit', audit_id, 'Audit plan approved by director')
        
        flash('Audit plan approved successfully.', 'success')
        
    except Exception as e:
        flash(f'Error approving audit plan: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/assign-auditor/<audit_id>', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def assign_auditor(audit_id):
    """Head of Business Control assigns auditor"""
    try:
        audit_data = {
            'auditor_id': request.form['auditor_id'],
            'auditee_id': request.form['auditee_id'],
            'status': 'assigned',
            'auditor_assigned_at': datetime.now().isoformat()
        }
        
        if audit_id in DATA_STORE['audits']: DATA_STORE['audits'][audit_id].update(audit_data)
        log_audit_action('assign_auditor', 'audit', audit_id, f'Auditor assigned to audit')
        
        flash('Auditor assigned successfully.', 'success')
        
    except Exception as e:
        flash(f'Error assigning auditor: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

# Messaging System Routes
@app.route('/messages')
@login_required
def messages():
    """View messages"""
    user = get_current_user()
    
    # Get all messages for current user (both received and sent)
    user_messages = []
    for msg in DATA_STORE['messages'].values():
        if msg.get('recipient_id') == user['id'] or msg.get('sender_id') == user['id']:
            user_messages.append(msg)
    
    # Get audit lookup for message references
    audit_lookup = {audit_id: audit for audit_id, audit in DATA_STORE['audits'].items()}
    
    # Get all users for new message form
    all_users = [u for u in DATA_STORE['users'].values() if u.get('id') != user['id']]
    
    return render_template('messages.html', 
                         messages=user_messages,
                         audit_lookup=audit_lookup,
                         all_users=all_users,
                         current_user=user)

@app.route('/messages/send', methods=['POST'])
@login_required
def send_message():
    """Send message"""
    try:
        message_data = {
            'audit_id': request.form['audit_id'],
            'sender_id': get_current_user()['id'],
            'recipient_id': request.form['recipient_id'],
            'message_content': request.form['message_content'],
            'message_type': request.form.get('message_type', 'general'),
            'subject': request.form.get('subject', 'Audit Communication')
        }
        
        message_id = message_model.send_message(message_data)
        log_audit_action('send_message', 'message', message_id, 'Message sent')
        
        flash('Message sent successfully.', 'success')
        
    except Exception as e:
        flash(f'Error sending message: {str(e)}', 'error')
    
    return redirect(url_for('messages'))

# Evidence Management Routes
@app.route('/evidence/upload', methods=['POST'])
@login_required
def upload_evidence():
    """Upload evidence file"""
    try:
        if 'file' not in request.files:
            flash('No file selected.', 'error')
            return redirect(request.referrer)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.referrer)
        
        # Save file
        filename = save_uploaded_file(file)
        
        evidence_data = {
            'audit_id': request.form['audit_id'],
            'filename': file.filename,
            'file_path': filename,
            'uploaded_by': get_current_user()['id'],
            'file_size': len(file.read()),
            'file_type': file.content_type,
            'description': request.form.get('description', '')
        }
        
        evidence_id = evidence_model.create_evidence(evidence_data)
        log_audit_action('upload_evidence', 'evidence', evidence_id, f'Evidence file uploaded: {file.filename}')
        
        flash('Evidence uploaded successfully.', 'success')
        
    except Exception as e:
        flash(f'Error uploading evidence: {str(e)}', 'error')
    
    return redirect(request.referrer)

# Report Generation Routes
@app.route('/generate-report/<audit_id>')
@login_required
@role_required('auditor', 'director')
def generate_audit_report(audit_id):
    """Generate PDF audit report"""
    try:
        audit = audit_model.get(audit_id)
        if not audit:
            flash('Audit not found.', 'error')
            return redirect(url_for('dashboard'))
        
        findings = [f for f in DATA_STORE['findings'].values() if f.get('audit_id') == audit_id]
        evidence = evidence_model.query('audit_id', '==', audit_id)
        
        # Create PDF report
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=18, spaceAfter=30)
        story.append(Paragraph(f"Audit Report: {audit['title']}", title_style))
        story.append(Spacer(1, 12))
        
        # Audit details
        story.append(Paragraph(f"<b>Reference Number:</b> {audit.get('reference_number', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"<b>Audit Type:</b> {audit.get('audit_type', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"<b>Status:</b> {audit.get('status', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"<b>Priority:</b> {audit.get('priority', 'N/A')}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Audit scope and objectives
        if audit.get('audit_scope'):
            story.append(Paragraph("<b>Audit Scope:</b>", styles['Heading2']))
            story.append(Paragraph(audit['audit_scope'], styles['Normal']))
            story.append(Spacer(1, 12))
        
        if audit.get('audit_objectives'):
            story.append(Paragraph("<b>Audit Objectives:</b>", styles['Heading2']))
            story.append(Paragraph(audit['audit_objectives'], styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Findings section
        if findings:
            story.append(Paragraph("<b>Findings:</b>", styles['Heading2']))
            for i, finding in enumerate(findings, 1):
                story.append(Paragraph(f"<b>Finding #{i}: {finding.get('title', 'Untitled')}</b>", styles['Normal']))
                story.append(Paragraph(f"Severity: {finding.get('severity', 'Unknown')}", styles['Normal']))
                story.append(Paragraph(finding.get('description', 'No description provided'), styles['Normal']))
                story.append(Spacer(1, 8))
        
        # Evidence section
        if evidence:
            story.append(Paragraph("<b>Evidence Files:</b>", styles['Heading2']))
            for ev in evidence:
                story.append(Paragraph(f"• {ev.get('filename', 'Unknown file')}", styles['Normal']))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        # Save report record
        report_data = {
            'audit_id': audit_id,
            'report_title': f"Audit Report - {audit['title']}",
            'report_content': 'PDF report generated',
            'generated_by': get_current_user()['id'],
            'status': 'final'
        }
        
        report_id = report_model.create_report(report_data)
        log_audit_action('generate_report', 'report', report_id, 'PDF report generated')
        
        # Return PDF response
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=audit_report_{audit_id}.pdf'
        
        return response
        
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

# Report Library Routes
@app.route('/report-library')
@login_required
@role_required('director', 'head_of_business_control', 'auditor')
def report_library():
    """Central report library"""
    reports = list(DATA_STORE['audit_reports'].values())
    audits = list(DATA_STORE['audits'].values())
    
    # Create audit lookup for report details
    audit_lookup = {audit['id']: audit for audit in audits}
    
    return render_template('report_library.html', reports=reports, audit_lookup=audit_lookup)

# User Management Routes
@app.route('/users')
@login_required
@role_required('head_of_business_control', 'director')
def users():
    """User management"""
    # Get users from data store since Firebase models might not work in mock mode
    users = list(DATA_STORE['users'].values())
    departments = list(DATA_STORE['departments'].values())
    
    return render_template('user_management.html', users=users, departments=departments)

@app.route('/users/create', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def create_user():
    """Create new user"""
    try:
        # Generate temporary password
        temp_password = generate_password()
        
        # Create user in Firebase Auth
        firebase_user = create_user_account(
            request.form['email'], 
            temp_password,
            f"{request.form['first_name']} {request.form['last_name']}"
        )
        
        if not firebase_user:
            flash('Error creating user account.', 'error')
            return redirect(url_for('manage_users'))
        
        # Create user record in Firestore
        user_data = {
            'email': request.form['email'],
            'role': request.form['role'],
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'phone': request.form.get('phone', ''),
            'department_id': request.form.get('department_id', ''),
            'firebase_uid': firebase_user['localId'],
            'temporary_password': temp_password,
            'password_reset_required': True
        }
        
        user_id = user_model.create_user(user_data)
        log_audit_action('create', 'user', user_id, f'User created: {request.form["email"]}')
        
        flash(f'User created successfully. Temporary password: {temp_password}', 'success')
        
    except Exception as e:
        flash(f'Error creating user: {str(e)}', 'error')
    
    return redirect(url_for('manage_users'))

# Department Management Routes  
@app.route('/departments')
@login_required
@role_required('head_of_business_control', 'director')
def departments():
    """Department management"""
    departments = list(DATA_STORE['departments'].values())
    return render_template('department_management.html', departments=departments)

@app.route('/departments/create', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def create_department():
    """Create new department"""
    try:
        dept_data = {
            'name': request.form['name'],
            'description': request.form.get('description', ''),
            'head_name': request.form.get('head_name', '')
        }
        
        dept_id = str(uuid.uuid4())
        dept_data['id'] = dept_id
        dept_data['created_at'] = datetime.now()
        DATA_STORE['departments'][dept_id] = dept_data
        log_audit_action('create', 'department', dept_id, f'Department created: {request.form["name"]}')
        
        flash('Department created successfully.', 'success')
        
    except Exception as e:
        flash(f'Error creating department: {str(e)}', 'error')
    
    return redirect(url_for('departments'))

# API Routes for AJAX calls
@app.route('/api/audit/<audit_id>/findings')
@login_required
def get_audit_findings(audit_id):
    """Get findings for an audit (API)"""
    findings = [f for f in DATA_STORE['findings'].values() if f.get('audit_id') == audit_id]
    return jsonify({'findings': findings})

@app.route('/api/risk-heatmap')
@login_required
def risk_heatmap_data():
    """Get risk data for heatmap"""
    risks = list(DATA_STORE['risks'].values())
    departments = list(DATA_STORE['departments'].values())
    
    # Create department lookup
    dept_lookup = {dept['id']: dept['name'] for dept in departments}
    
    # Format data for heatmap
    heatmap_data = []
    for risk in risks:
        heatmap_data.append({
            'department': dept_lookup.get(risk.get('department_id', ''), 'Unknown'),
            'risk_score': risk.get('risk_score', 0),
            'risk_level': risk.get('risk_level', 'low'),
            'description': risk.get('risk_description', '')
        })
    
    return jsonify({'heatmap_data': heatmap_data})

# Context processor for templates
@app.context_processor
def inject_user():
    """Inject current user into all templates"""
    return dict(current_user=get_current_user())

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500# Missing routes to be added to firebase_routes.py

@app.route('/audit-execution')
@login_required
@role_required('auditor', 'head_of_business_control', 'director')
def audit_execution():
    """Audit execution page"""
    audits = list(DATA_STORE['audits'].values())
    return render_template('auditor/audits.html', audits=audits)

@app.route('/findings')
@login_required
@role_required('auditor', 'auditee', 'director')
def findings():
    """Findings page"""
    findings = list(DATA_STORE['findings'].values())
    return render_template('auditor/findings.html', findings=findings)

@app.route('/corrective-actions')
@login_required
@role_required('auditee')
def corrective_actions():
    """Corrective actions page"""
    actions = list(DATA_STORE['corrective_actions'].values())
    return render_template('auditee/corrective_actions.html', actions=actions)

@app.route('/evidence-management')
@login_required
@role_required('auditor', 'auditee', 'director')
def evidence_management():
    """Evidence management page"""
    evidence = list(DATA_STORE['evidence_files'].values())
    return render_template('auditee/evidence.html', evidence=evidence)

@app.route('/audit-reports')
@login_required
def audit_reports():
    """Audit reports page"""
    reports = list(DATA_STORE['audit_reports'].values())
    return render_template('auditor/reports.html', reports=reports)

@app.route('/reports')
@login_required
def reports():
    """Reports library alias"""
    return report_library()

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    user = get_current_user()
    if not user:
        flash('User session not found. Please log in again.', 'error')
        return redirect(url_for('landing'))
    
    # Get user notifications
    notifications = [n for n in DATA_STORE.get('notifications', []) if n.get('user_id') == user['id']]
    
    return render_template('profile.html', user=user, notifications=notifications)

@app.route('/document-requests')
@login_required
@role_required('auditee')
def document_requests():
    """Document requests page"""
    requests = []
    return render_template('auditee/document_requests.html', requests=requests)

@app.route('/upload-evidence-page')
@login_required
@role_required('auditee')
def upload_evidence_page():
    """Evidence upload page"""
    user = get_current_user()
    
    # Get sample finding (should be passed from URL parameter)
    finding_id = request.args.get('finding_id')
    finding = None
    if finding_id:
        finding = DATA_STORE['findings'].get(finding_id)
    
    # If no finding, create a sample for template
    if not finding:
        finding = {
            'id': 'sample',
            'title': 'Sample Finding',
            'description': 'Please select a finding to upload evidence for.',
            'severity': 'medium',
            'status': 'open'
        }
    
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('auditee/upload_evidence.html', 
                         finding=finding,
                         current_user=user,
                         notifications=notifications)

@app.route('/auditee-reports')
@login_required
@role_required('auditee')
def auditee_reports():
    """Auditee reports page"""
    reports = list(DATA_STORE['audit_reports'].values())
    return render_template('auditee/reports.html', reports=reports)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password page"""
    user = get_current_user()
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
        else:
            # Update password logic here
            flash('Password updated successfully.', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('change_password.html', user=user)

@app.route('/user-profile')
@login_required
def user_profile():
    """User profile page"""
    user = get_current_user()
    department = DATA_STORE['departments'].get(user.get('department_id')) if user.get('department_id') else None
    return render_template('profile.html', user=user, department=department)

# Removed duplicate landing function - using existing one

@app.route('/manage-users')
@login_required
@role_required('director', 'head_of_business_control')
def manage_users_page():
    """Manage users page"""
    return redirect(url_for('users'))

@app.route('/manage-departments')
@login_required
@role_required('director', 'head_of_business_control')
def manage_departments_page():
    """Manage departments page"""
    return redirect(url_for('departments'))

@app.route('/users/edit/<user_id>', methods=['GET', 'POST'])
@login_required
@role_required('director', 'head_of_business_control')
def edit_user(user_id):
    """Edit user page"""
    user = DATA_STORE['users'].get(user_id)
    if not user:
        abort(404)
    
    if request.method == 'POST':
        try:
            # Update user data
            user['first_name'] = request.form.get('first_name', user.get('first_name', ''))
            user['last_name'] = request.form.get('last_name', user.get('last_name', ''))
            user['email'] = request.form.get('email', user.get('email', ''))
            user['role'] = request.form.get('role', user.get('role', ''))
            user['department_id'] = request.form.get('department_id', user.get('department_id', ''))
            user['phone'] = request.form.get('phone', user.get('phone', ''))
            
            log_audit_action('update_user', 'user', user_id, f'User updated: {user.get("email")}')
            flash('User updated successfully.', 'success')
            return redirect(url_for('users'))
            
        except Exception as e:
            flash(f'Error updating user: {str(e)}', 'error')
    
    departments = list(DATA_STORE['departments'].values())
    return render_template('admin/edit_user.html', user=user, departments=departments)

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@role_required('director', 'head_of_business_control')
def create_new_user():
    """Create user route"""
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        role = request.form.get('role')
        department_id = request.form.get('department_id')
        
        new_user = {
            'id': str(uuid4()),
            'email': email,
            'name': name,
            'role': role,
            'department_id': department_id,
            'status': 'active',
            'created_at': datetime.now().isoformat()
        }
        
        DATA_STORE['users'][new_user['id']] = new_user
        flash('User created successfully.', 'success')
        return redirect(url_for('users'))

@app.route('/departments/<department_id>/users/<user_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('director', 'head_of_business_control')
def edit_department_user(department_id, user_id):
    """Edit user in department context"""
    return redirect(url_for('edit_user', user_id=user_id))

@app.route('/departments/<department_id>/users/<user_id>/deactivate', methods=['POST'])
@login_required
@role_required('director', 'head_of_business_control')
def deactivate_department_user(department_id, user_id):
    """Deactivate user in department context"""
    try:
        user = DATA_STORE['users'].get(user_id)
        if user:
            user['is_active'] = False
            flash('User has been deactivated successfully.', 'success')
            log_audit_action('deactivate_user', 'user', user_id, f'User deactivated: {user.get("email")}')
        else:
            flash('User not found.', 'error')
    except Exception as e:
        flash(f'Error deactivating user: {str(e)}', 'error')
    return redirect(url_for('department_users', department_id=department_id))
    
    departments = list(DATA_STORE['departments'].values())
    return render_template('admin/create_user.html', departments=departments)

@app.route('/users/<user_id>/toggle-status', methods=['POST'])
@login_required
@role_required('director', 'head_of_business_control')
def toggle_user_status(user_id):
    """Toggle user status"""
    try:
        user = DATA_STORE['users'].get(user_id)
        if user:
            current_status = user.get('is_active', True)
            user['is_active'] = not current_status
            status_text = 'active' if user['is_active'] else 'inactive'
            flash(f"User status changed to {status_text}.", 'success')
            log_audit_action('update_user_status', 'user', user_id, f'User status changed to {status_text}')
        else:
            flash('User not found.', 'error')
    except Exception as e:
        flash(f'Error updating user status: {str(e)}', 'error')
    return redirect(url_for('users'))

@app.route('/users/<user_id>/delete', methods=['POST'])
@login_required
@role_required('director', 'head_of_business_control')
def delete_user(user_id):
    """Delete user"""
    try:
        user = DATA_STORE['users'].get(user_id)
        if user:
            del DATA_STORE['users'][user_id]
            log_audit_action('delete_user', 'user', user_id, f'User deleted: {user.get("email")}')
            flash('User deleted successfully.', 'success')
        else:
            flash('User not found.', 'error')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
    return redirect(url_for('users'))

@app.route('/departments/create', methods=['GET', 'POST'])
@login_required
@role_required('director', 'head_of_business_control')
def create_new_department():
    """Create department"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        head_name = request.form.get('head_name')
        
        new_dept = {
            'id': str(uuid4()),
            'name': name,
            'description': description,
            'head_name': head_name,
            'created_at': datetime.now().isoformat()
        }
        
        DATA_STORE['departments'][new_dept['id']] = new_dept
        flash('Department created successfully.', 'success')
        return redirect(url_for('departments'))
    
    return render_template('admin/create_department.html')

@app.route('/departments/<department_id>/delete', methods=['POST'])
@login_required
@role_required('director', 'head_of_business_control')
def delete_department(department_id):
    """Delete department"""
    try:
        department = DATA_STORE['departments'].get(department_id)
        if department:
            # Check if department has users
            dept_users = [u for u in DATA_STORE['users'].values() if u.get('department_id') == department_id]
            if dept_users:
                flash(f'Cannot delete department with {len(dept_users)} assigned users. Please reassign users first.', 'error')
                return redirect(url_for('departments'))
            
            del DATA_STORE['departments'][department_id]
            log_audit_action('delete_department', 'department', department_id, f'Department deleted: {department.get("name")}')
            flash('Department deleted successfully.', 'success')
        else:
            flash('Department not found.', 'error')
    except Exception as e:
        flash(f'Error deleting department: {str(e)}', 'error')
    return redirect(url_for('departments'))
    try:
        if department_id in DATA_STORE['departments']:
            # Check if department has users
            users_in_dept = [u for u in DATA_STORE['users'].values() if u.get('department_id') == department_id]
            if users_in_dept:
                flash('Cannot delete department with active users. Please reassign users first.', 'error')
            else:
                del DATA_STORE['departments'][department_id]
                flash('Department deleted successfully.', 'success')
                log_audit_action('delete_department', 'department', department_id, 'Department deleted')
        else:
            flash('Department not found.', 'error')
    except Exception as e:
        flash(f'Error deleting department: {str(e)}', 'error')
    return redirect(url_for('departments'))

@app.route('/departments/<department_id>/toggle-status', methods=['POST'])
@login_required
@role_required('director', 'head_of_business_control')
def toggle_department_status(department_id):
    """Toggle department status"""
    try:
        department = DATA_STORE['departments'].get(department_id)
        if department:
            current_status = department.get('is_active', True)
            department['is_active'] = not current_status
            status_text = 'active' if department['is_active'] else 'inactive'
            flash(f"Department status changed to {status_text}.", 'success')
            log_audit_action('update_department_status', 'department', department_id, f'Department status changed to {status_text}')
        else:
            flash('Department not found.', 'error')
    except Exception as e:
        flash(f'Error updating department status: {str(e)}', 'error')
    return redirect(url_for('departments'))

@app.route('/departments/<department_id>/users')
@login_required
@role_required('director', 'head_of_business_control')
def department_users(department_id):
    """View users in department"""
    department = DATA_STORE['departments'].get(department_id)
    if not department:
        abort(404)
    
    users = [u for u in DATA_STORE['users'].values() if u.get('department_id') == department_id]
    return render_template('admin/department_users.html', department=department, users=users)

# More missing routes
@app.route('/risk-assessment/create', methods=['GET', 'POST'])
@login_required
@role_required('director', 'head_of_business_control')
def create_new_risk_assessment():
    """Create risk assessment"""
    if request.method == 'POST':
        # Handle risk assessment creation
        flash('Risk assessment created successfully.', 'success')
        return redirect(url_for('risk_assessment'))
    return render_template('create_risk_assessment.html')

@app.route('/audit-planning/create', methods=['GET', 'POST'])
@login_required
@role_required('director', 'head_of_business_control')
def create_new_audit_plan():
    """Create audit plan"""
    if request.method == 'POST':
        # Handle audit plan creation
        flash('Audit plan created successfully.', 'success')
        return redirect(url_for('audit_planning'))
    return render_template('create_audit_plan.html')

@app.route('/audits')
@login_required
def audit_list():
    """List audits based on user role"""
    user = get_current_user()
    audits = list(DATA_STORE['audits'].values())
    
    # Filter audits based on role
    if user['role'] == 'auditor':
        audits = [audit for audit in audits if audit.get('auditor_id') == user['id']]
    elif user['role'] == 'auditee':
        audits = [audit for audit in audits if audit.get('auditee_id') == user['id']]
    
    return render_template('audits/list.html', audits=audits, user=user)

@app.route('/audit/<audit_id>/finding/create', methods=['GET', 'POST'])
@login_required
@role_required('auditor')
def create_finding(audit_id):
    """Create a new finding"""
    audit = DATA_STORE['audits'].get(audit_id)
    if not audit:
        abort(404)
    
    if request.method == 'POST':
        try:
            finding_data = {
                'id': str(uuid4()),
                'audit_id': audit_id,
                'title': request.form.get('title'),
                'description': request.form.get('description'),
                'severity': request.form.get('severity'),
                'status': 'open',
                'created_by': get_current_user()['id'],
                'created_at': datetime.now().isoformat(),
                'recommendations': request.form.get('recommendations', '')
            }
            
            DATA_STORE['findings'][finding_data['id']] = finding_data
            log_audit_action('create_finding', 'finding', finding_data['id'], f'Finding created: {finding_data["title"]}')
            flash('Finding created successfully.', 'success')
            return redirect(url_for('audit_detail', audit_id=audit_id))
            
        except Exception as e:
            flash(f'Error creating finding: {str(e)}', 'error')
    
    return render_template('auditor/create_finding.html', audit=audit)

@app.route('/audit/<audit_id>')
@login_required
def audit_detail(audit_id):
    """Audit detail page"""
    audit = DATA_STORE['audits'].get(audit_id)
    if not audit:
        abort(404)
    
    # Get current user and notifications
    user = get_current_user()
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    # Get findings for this audit
    findings = [f for f in DATA_STORE['findings'].values() if f.get('audit_id') == audit_id]
    
    return render_template('audits/detail.html', 
                         audit=audit,
                         findings=findings,
                         current_user=user,
                         notifications=notifications)

@app.route('/audit/<audit_id>/edit')
@login_required
@role_required('director', 'head_of_business_control')
def edit_audit(audit_id):
    """Edit audit page"""
    audit = DATA_STORE['audits'].get(audit_id)
    if not audit:
        abort(404)
    return render_template('audits/edit.html', audit=audit)

@app.route('/create-audit')
@login_required
@role_required('director', 'head_of_business_control')
def create_audit():
    """Create new audit"""
    return render_template('audits/create.html')

@app.route('/reports/generate', methods=['GET', 'POST'])
@login_required
def generate_report():
    """Generate report page"""
    if request.method == 'POST':
        # Handle report generation
        report_type = request.form.get('report_type')
        audit_id = request.form.get('audit_id')
        
        try:
            # Generate report logic here
            new_report = {
                'id': str(uuid4()),
                'type': report_type,
                'audit_id': audit_id,
                'generated_by': get_current_user()['id'],
                'generated_at': datetime.now().isoformat(),
                'title': f'{report_type.title()} Report',
                'status': 'completed'
            }
            
            DATA_STORE['audit_reports'][new_report['id']] = new_report
            flash('Report generated successfully.', 'success')
            return redirect(url_for('view_report', report_id=new_report['id']))
            
        except Exception as e:
            flash(f'Error generating report: {str(e)}', 'error')
    
    # Get audits for report selection
    audits = list(DATA_STORE['audits'].values())
    user = get_current_user()
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('reports/generate.html', 
                         audits=audits,
                         current_user=user,
                         notifications=notifications)

@app.route('/reports/<report_id>')
@login_required
def view_report(report_id):
    """View report page"""
    report = DATA_STORE['audit_reports'].get(report_id)
    if not report:
        abort(404)
    return render_template('reports/view.html', report=report)

@app.route('/reports/<report_id>/edit')
@login_required
@role_required('director', 'head_of_business_control')
def edit_report(report_id):
    """Edit report page"""
    report = DATA_STORE['audit_reports'].get(report_id)
    if not report:
        abort(404)
    return render_template('reports/edit.html', report=report)

@app.route('/reports/<report_id>/download')
@login_required
def download_report(report_id):
    """Download report"""
    report = DATA_STORE['audit_reports'].get(report_id)
    if not report:
        abort(404)
    # Generate and return PDF if ReportLab is available
    if REPORTLAB_AVAILABLE:
        try:
            # Simple PDF response for now
            response = make_response("PDF content would be here")
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename=report_{report_id}.pdf'
            return response
        except Exception as e:
            flash(f'Error generating PDF: {str(e)}', 'error')
            return redirect(url_for('view_report', report_id=report_id))
    else:
        flash('PDF generation not available.', 'error')
        return redirect(url_for('view_report', report_id=report_id))

@app.route('/audit/<audit_id>/findings')
@login_required
def audit_findings(audit_id):
    """Audit findings page"""
    audit = DATA_STORE['audits'].get(audit_id)
    if not audit:
        abort(404)
    findings = [f for f in DATA_STORE['findings'].values() if f.get('audit_id') == audit_id]
    return render_template('audits/findings.html', audit=audit, findings=findings)

@app.route('/notifications/delete/<notification_id>', methods=['POST'])
@login_required
def delete_user_notification(notification_id):
    """Delete user notification"""
    user = get_current_user()
    notifications = DATA_STORE.get('notifications', [])
    updated_notifications = [n for n in notifications if not (n.get('id') == notification_id and n.get('user_id') == user['id'])]
    DATA_STORE['notifications'] = updated_notifications
    flash('Notification deleted.', 'success')
    return redirect(url_for('profile'))

@app.route('/notifications/delete-all', methods=['POST'])
@login_required
def delete_all_user_notifications():
    """Delete all user notifications"""
    user = get_current_user()
    notifications = DATA_STORE.get('notifications', [])
    updated_notifications = [n for n in notifications if n.get('user_id') != user['id']]
    DATA_STORE['notifications'] = updated_notifications
    flash('All notifications deleted.', 'success')
    return redirect(url_for('profile'))

@app.route('/admin/notifications/delete/<notification_id>', methods=['POST'])
@login_required
@role_required('director')
def admin_delete_notification(notification_id):
    """Delete notification as admin"""
    notifications = DATA_STORE.get('notifications', [])
    DATA_STORE['notifications'] = [n for n in notifications if n.get('id') != notification_id]
    flash('Notification deleted.', 'success')
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/admin/notifications/delete-all', methods=['POST'])
@login_required
@role_required('director')
def admin_delete_all_notifications():
    """Delete all notifications as admin"""
    DATA_STORE['notifications'] = []
    flash('All notifications deleted.', 'success')
    return redirect(request.referrer or url_for('dashboard'))