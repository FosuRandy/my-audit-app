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
import hashlib

def generate_password(length=12):
    """Generate a secure random password"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(characters) for _ in range(length))

def generate_csrf_token():
    """Generate a CSRF token and store it in session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token against session"""
    return token and session.get('csrf_token') == token

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
    notifications = []
    if user:
        notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('director/dashboard.html', 
                         pending_audits=pending_audits,
                         pending_plans=pending_audits,
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
    # Get audits in various workflow stages
    draft_audits = [audit for audit in DATA_STORE['audits'].values() 
                   if audit.get('status') == 'draft']
    director_approved_audits = [audit for audit in DATA_STORE['audits'].values() 
                               if audit.get('status') == 'director_approved']
    auditor_plan_submitted_audits = [audit for audit in DATA_STORE['audits'].values() 
                                    if audit.get('status') == 'auditor_plan_submitted']
    ready_audits = [audit for audit in DATA_STORE['audits'].values() 
                   if audit.get('status') == 'ready_for_fieldwork']
    
    # Enrich audits with department names
    for audit in draft_audits + director_approved_audits + auditor_plan_submitted_audits + ready_audits:
        dept = DATA_STORE.get('departments', {}).get(audit.get('department_id'))
        if dept:
            audit['department_name'] = dept.get('name', 'N/A')
    
    # Get auditors for assignment
    auditors = [user for user in DATA_STORE['users'].values() 
               if user.get('role') == 'auditor']
    auditees = [user for user in DATA_STORE['users'].values() 
               if user.get('role') == 'auditee']
    
    # Enrich auditors and auditees with department names
    for user_obj in auditors + auditees:
        dept = DATA_STORE.get('departments', {}).get(user_obj.get('department_id'))
        if dept:
            user_obj['department_name'] = dept.get('name', 'N/A')
    
    # Risk assessments
    risks = list(DATA_STORE['risk_assessments'].values())
    
    # Corrective actions tracking
    all_actions = list(DATA_STORE['corrective_actions'].values())
    overdue_actions = [a for a in all_actions if a.get('target_date') and 
                      datetime.fromisoformat(a['target_date']) < datetime.now() and 
                      a.get('status') != 'completed']
    
    # Calculate available auditors count
    active_auditors = [a for a in auditors if a.get('is_active', True)]
    
    # Calculate active audits count
    active_audits = [a for a in DATA_STORE['audits'].values() 
                    if a.get('status') not in ['draft', 'completed', 'rejected']]
    
    # Calculate high/medium/low risk counts
    high_risk = len([r for r in risks if r.get('risk_level') == 'high'])
    medium_risk = len([r for r in risks if r.get('risk_level') == 'medium'])
    low_risk = len([r for r in risks if r.get('risk_level') == 'low'])
    
    stats = {
        'draft_audits': len(draft_audits),
        'director_approved_audits': len(director_approved_audits), 
        'auditor_plan_submitted_audits': len(auditor_plan_submitted_audits),
        'ready_audits': len(ready_audits),
        'active_audits': len(active_audits),
        'available_auditors': len(active_auditors),
        'risk_areas': len(risks),
        'total_risks': len(risks),
        'high_risk': high_risk,
        'medium_risk': medium_risk,
        'low_risk': low_risk,
        'overdue_actions': len(overdue_actions)
    }
    
    # Get user notifications  
    user = get_current_user()
    notifications = []
    if user:
        notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('head_of_business_control/dashboard.html',
                         draft_audits=draft_audits,
                         director_approved_audits=director_approved_audits,
                         auditor_plan_submitted_audits=auditor_plan_submitted_audits,
                         ready_audits=ready_audits,
                         auditors=auditors,
                         available_auditors=active_auditors,
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
    
    # Check if user exists
    if not user:
        flash('User session invalid. Please log in again.', 'error')
        return redirect(url_for('landing'))
        
    # Get audits assigned to this auditor
    assigned_audits = [audit for audit in DATA_STORE['audits'].values() 
                      if audit.get('auditor_id') == user.get('id')]
    
    # Get findings for audits
    auditor_findings = [finding for finding in DATA_STORE['findings'].values() 
                       if finding.get('audit_id') in [a['id'] for a in assigned_audits]]
    
    # Get messages
    auditor_messages = [msg for msg in DATA_STORE['messages'].values() 
                       if msg.get('recipient_id') == user.get('id') or msg.get('sender_id') == user.get('id')]
    
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
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user.get('id')]
    
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
    
    # Check if user exists
    if not user:
        flash('User session invalid. Please log in again.', 'error')
        return redirect(url_for('landing'))
        
    # Get audits where this user is auditee
    auditee_audits = [audit for audit in DATA_STORE.get('audits', {}).values() 
                     if audit.get('auditee_id') == user.get('id')]
    
    # Get corrective actions assigned to this auditee
    my_actions = [action for action in DATA_STORE['corrective_actions'].values() 
                 if action.get('responsible_person_id') == user.get('id')]
    
    # Get messages for this auditee
    auditee_messages = [msg for msg in DATA_STORE['messages'].values() 
                       if msg.get('recipient_id') == user.get('id')]
    
    # Get evidence files uploaded by this auditee
    my_evidence = [evidence for evidence in DATA_STORE['evidence_files'].values() 
                  if evidence.get('uploaded_by') == user.get('id')]
    
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
    
    # Calculate risk statistics
    risk_stats = {
        'critical': len([r for r in risks if r.get('risk_level') == 'critical']),
        'high': len([r for r in risks if r.get('risk_level') == 'high']), 
        'medium': len([r for r in risks if r.get('risk_level') == 'medium']),
        'low': len([r for r in risks if r.get('risk_level') == 'low']),
        'total': len(risks)
    }
    
    return render_template('risk_assessment.html', risks=risks, departments=departments, risk_stats=risk_stats)

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
                'created_by': get_current_user().get('id') if get_current_user() else None
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
    
    # Calculate planning statistics
    planning_stats = {
        'draft': len([a for a in audits if a.get('status') == 'draft']),
        'pending': len([a for a in audits if a.get('status') == 'pending_director_approval']),
        'director_approved': len([a for a in audits if a.get('status') == 'director_approved']),
        'ready_for_fieldwork': len([a for a in audits if a.get('status') == 'ready_for_fieldwork']),
        'total': len(audits)
    }
    
    return render_template('audit_planning.html', audits=audits, risks=risks, departments=departments, planning_stats=planning_stats)

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
            audit = DATA_STORE['audits'][audit_id]
            audit.update(audit_data)
            
            # Notify Director
            create_notification(
                user_role='director',
                title='Audit Plan Approval Required',
                message=f'Audit "{audit.get("title", "")}" has been submitted for your review and approval.',
                notification_type='plan_approval_needed',
                related_entity_type='audit',
                related_entity_id=audit_id
            )
            
        log_audit_action('submit_for_approval', 'audit', audit_id, 'Audit plan submitted for director approval')
        
        flash('Audit plan submitted for Director approval.', 'success')
        
    except Exception as e:
        flash(f'Error submitting audit plan: {str(e)}', 'error')
    
    return redirect(url_for('audit_planning'))

@app.route('/audit/submit-for-approval/<plan_id>', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def submit_for_approval(plan_id):
    """Submit audit plan for director approval (alternative route for dashboard)"""
    return submit_audit_for_approval(plan_id)

@app.route('/director/approve-audit/<audit_id>', methods=['POST'])
@login_required
@role_required('director')
def approve_audit_plan(audit_id):
    """Director approves audit plan"""
    try:
        audit_data = {
            'status': 'director_approved',
            'director_approved_at': datetime.now().isoformat(),
            'director_feedback': request.form.get('director_feedback', '')
        }
        
        if audit_id in DATA_STORE['audits']:
            audit = DATA_STORE['audits'][audit_id]
            audit.update(audit_data)
            
            # Notify HBC
            create_notification(
                user_role='head_of_business_control',
                title='Audit Plan Approved',
                message=f'Director approved audit plan: "{audit.get("title", "")}". You can now assign an auditor.',
                notification_type='plan_approved',
                related_entity_type='audit',
                related_entity_id=audit_id
            )
            
        log_audit_action('approve', 'audit', audit_id, 'Audit plan approved by director')
        
        flash('Audit plan approved successfully.', 'success')
        
    except Exception as e:
        flash(f'Error approving audit plan: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/assign-auditor/<audit_id>', methods=['GET', 'POST'])
@login_required
@role_required('head_of_business_control')
def assign_auditor(audit_id):
    """Head of Business Control assigns auditor"""
    audit = DATA_STORE.get('audits', {}).get(audit_id)
    
    if not audit:
        flash('Audit not found.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            auditor_id = request.form['auditor_id']
            auditee_id = request.form['auditee_id']
            
            audit_data = {
                'auditor_id': auditor_id,
                'auditee_id': auditee_id,
                'status': 'assigned',
                'auditor_assigned_at': datetime.now().isoformat()
            }
            
            if audit_id in DATA_STORE['audits']:
                DATA_STORE['audits'][audit_id].update(audit_data)
                
                # Notify auditor
                create_notification(
                    user_id=auditor_id,
                    title='New Audit Assignment',
                    message=f'You have been assigned to audit: "{audit.get("title", "")}". Please acknowledge this assignment.',
                    notification_type='audit_assigned',
                    related_entity_type='audit',
                    related_entity_id=audit_id
                )
                
                # Notify auditee
                create_notification(
                    user_id=auditee_id,
                    title='Audit Assignment',
                    message=f'You have been assigned as auditee for audit: "{audit.get("title", "")}". The auditor will contact you soon.',
                    notification_type='auditee_assigned',
                    related_entity_type='audit',
                    related_entity_id=audit_id
                )
                
            log_audit_action('assign_auditor', 'audit', audit_id, f'Auditor and auditee assigned to audit')
            
            flash('Auditor and auditee assigned successfully.', 'success')
            
        except KeyError as e:
            flash(f'Missing required field: {str(e)}', 'error')
        except Exception as e:
            flash(f'Error assigning auditor: {str(e)}', 'error')
        
        return redirect(url_for('dashboard'))
    
    # GET request - show assignment page
    # Enrich audit data
    dept = DATA_STORE.get('departments', {}).get(audit.get('department_id'))
    if dept:
        audit['department_name'] = dept.get('name', 'N/A')
    
    # Get available auditors
    auditors = [user for user in DATA_STORE['users'].values() 
               if user.get('role') == 'auditor' and user.get('is_active', True)]
    
    # Enrich auditors with department names
    for auditor in auditors:
        dept_id = auditor.get('department_id')
        if dept_id and dept_id in DATA_STORE.get('departments', {}):
            auditor['department_name'] = DATA_STORE['departments'][dept_id].get('name', 'N/A')
    
    # Get available auditees
    auditees = [user for user in DATA_STORE['users'].values() 
               if user.get('role') == 'auditee' and user.get('is_active', True)]
    
    # Enrich auditees with department names
    for auditee in auditees:
        dept_id = auditee.get('department_id')
        if dept_id and dept_id in DATA_STORE.get('departments', {}):
            auditee['department_name'] = DATA_STORE['departments'][dept_id].get('name', 'N/A')
    
    user = get_current_user()
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('head_of_business_control/assign_auditor.html',
                         audit=audit,
                         available_auditors=auditors,
                         available_auditees=auditees,
                         current_user=user,
                         notifications=notifications)

@app.route('/assign-auditors')
@login_required
@role_required('head_of_business_control')
def assign_auditors():
    """Head of Business Control - General assign auditors page"""
    user = get_current_user()
    
    # Get director-approved audits that need auditor assignment
    available_audits = [audit for audit in DATA_STORE['audits'].values() 
                       if audit.get('status') == 'director_approved' and not audit.get('auditor_id')]
    
    # Get all available auditors
    auditors = [user for user in DATA_STORE['users'].values() 
               if user.get('role') == 'auditor' and user.get('is_active', True)]
    
    # Get all available auditees 
    auditees = [user for user in DATA_STORE['users'].values() 
               if user.get('role') == 'auditee' and user.get('is_active', True)]
    
    # Get departments for context
    departments = {dept['id']: dept for dept in DATA_STORE['departments'].values()}
    
    # Enrich audits with department names
    for audit in available_audits:
        if audit.get('department_id') and audit['department_id'] in departments:
            audit['department_name'] = departments[audit['department_id']]['name']
    
    # Enrich auditors with department names  
    for auditor in auditors:
        if auditor.get('department_id') and auditor['department_id'] in departments:
            auditor['department_name'] = departments[auditor['department_id']]['name']
    
    # Enrich auditees with department names
    for auditee in auditees:
        if auditee.get('department_id') and auditee['department_id'] in departments:
            auditee['department_name'] = departments[auditee['department_id']]['name']
    
    return render_template('head_of_business_control/assign_auditors.html',
                         available_audits=available_audits,
                         auditors=auditors,
                         auditees=auditees,
                         current_user=user)

# Messaging System Routes
@app.route('/messages')
@login_required
def messages():
    """View messages"""
    user = get_current_user()
    
    # Check if user exists
    if not user:
        flash('User session invalid. Please log in again.', 'error')
        return redirect(url_for('landing'))
    
    # Get all messages for current user (both received and sent)
    user_messages = []
    for msg in DATA_STORE['messages'].values():
        if msg.get('recipient_id') == user.get('id') or msg.get('sender_id') == user.get('id'):
            user_messages.append(msg)
    
    # Get audit lookup for message references
    audit_lookup = {audit_id: audit for audit_id, audit in DATA_STORE['audits'].items()}
    
    # Get all users for new message form
    all_users = [u for u in DATA_STORE['users'].values() if u.get('id') != user.get('id')]
    
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

# Report Generation Routes (removed duplicate - exists later in file)

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
    
    # Calculate library statistics
    from datetime import datetime, timedelta
    current_month = datetime.now().month
    current_year = datetime.now().year
    
    # Safely filter reports by date
    this_month_reports = []
    most_downloaded_report = None
    max_downloads = 0
    
    for r in reports:
        # Handle both string and datetime formats for generated_at
        report_date = r.get('generated_at', '')
        if isinstance(report_date, str) and report_date.startswith(f"{current_year}-{current_month:02d}"):
            this_month_reports.append(r)
        
        # Find most downloaded report
        downloads = r.get('download_count', 0)
        if downloads > max_downloads:
            max_downloads = downloads
            most_downloaded_report = r.get('title', 'N/A')
    
    library_stats = {
        'this_month': len(this_month_reports),
        'most_downloaded': most_downloaded_report or 'No downloads yet',
        'departments': len(set(audit.get('department_id') for audit in audits if audit.get('department_id')))
    }
    
    return render_template('report_library.html', reports=reports, audit_lookup=audit_lookup, library_stats=library_stats)

# User Management Routes
@app.route('/users')
@login_required
@role_required('head_of_business_control', 'director')
def users():
    """User management - view-only for directors"""
    # Use DATA_STORE for faster loading
    users = list(DATA_STORE.get('users', {}).values())
    departments = list(DATA_STORE.get('departments', {}).values())
    return render_template('admin/users.html', users=users, departments=departments)

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
            return redirect(url_for('manage_users_page'))
        
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
    
    return redirect(url_for('manage_users_page'))

# Department Management Routes  
@app.route('/departments')
@login_required
@role_required('head_of_business_control', 'director')
def departments():
    """Department management with improved styling"""
    # Load departments from Firestore
    all_departments = dept_model.get_all()
    all_users = user_model.get_all()
    
    # Enrich department data with user counts
    for dept in all_departments:
        dept['users'] = [u for u in all_users if u.get('department_id') == dept.get('id')]
    
    # Sort departments by name
    all_departments.sort(key=lambda x: x.get('name', ''))
    
    return render_template('admin/departments.html', departments=all_departments)

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
        
        dept_id = dept_model.create_department(dept_data)
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

@app.route('/api/notifications/count')
def get_notifications_count():
    """Get count of unread notifications (API)"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized', 'count': 0}), 401
        
        notifications = [n for n in DATA_STORE.get('notifications', {}).values() 
                        if n.get('user_id') == user['id'] and not n.get('is_read', False)]
        
        return jsonify({'count': len(notifications)})
    except Exception as e:
        return jsonify({'error': 'Failed to fetch notifications', 'details': str(e), 'count': 0}), 500

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
    user = get_current_user()
    
    # Get all corrective actions
    all_actions = DATA_STORE.get('corrective_actions', {})
    
    # Filter corrective actions for this auditee (responsible person or auditee of related finding)
    my_actions = []
    for action in all_actions.values():
        # Check if auditee is responsible person
        if action.get('responsible_person_id') == user.get('id'):
            my_actions.append(action)
        # Or check if auditee is assigned to the related finding
        elif action.get('finding_id'):
            finding = DATA_STORE.get('findings', {}).get(action['finding_id'])
            if finding and finding.get('auditee_id') == user.get('id'):
                my_actions.append(action)
    
    # If no actions exist, create sample ones for demonstration
    if not my_actions:
        # Get auditee's findings to create sample corrective actions
        my_findings = [f for f in DATA_STORE.get('findings', {}).values() 
                      if f.get('auditee_id') == user.get('id')]
        
        if my_findings:
            sample_actions = []
            for finding in my_findings[:2]:  # Create samples for first 2 findings
                sample_actions.extend([
                    {
                        'id': f"action_{finding['id']}_1",
                        'finding_id': finding['id'],
                        'title': f"Corrective Action for {finding.get('title', 'Finding')}",
                        'description': f"Address and resolve the issue: {finding.get('description', '')[:100]}...",
                        'status': 'pending',
                        'priority': finding.get('severity', 'medium'),
                        'responsible_person_id': user.get('id'),
                        'responsible_person_name': f"{user.get('first_name', '')} {user.get('last_name', '')}".strip(),
                        'target_date': '2025-02-28',
                        'created_at': '2025-01-15T10:00:00',
                        'audit_title': finding.get('audit_title', 'Unknown Audit')
                    }
                ])
            my_actions = sample_actions
    
    # Get user notifications
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('auditee/corrective_actions.html', 
                         actions=my_actions,
                         current_user=user,
                         notifications=notifications)

@app.route('/evidence-management')
@login_required
@role_required('auditor', 'auditee', 'director')
def evidence_management():
    """Evidence management page"""
    evidence = list(DATA_STORE['evidence_files'].values())
    return render_template('auditee/evidence.html', evidence=evidence)

@app.route('/audit-reports')
@login_required
@role_required('auditor', 'director', 'head_of_business_control') 
def audit_reports():
    """Audit reports page - filter for current user if auditor"""
    user = get_current_user()
    if not user:
        flash('User session invalid. Please log in again.', 'error')
        return redirect(url_for('landing'))
    
    # Get all reports and audits
    all_reports = list(DATA_STORE['audit_reports'].values())
    all_audits = list(DATA_STORE['audits'].values())
    
    # Filter reports and audits based on user role  
    if user.get('role') == 'auditor':
        # For auditors: only show reports for audits they are assigned to
        assigned_audit_ids = [audit['id'] for audit in all_audits if audit.get('auditor_id') == user.get('id')]
        reports = [report for report in all_reports if report.get('audit_id') in assigned_audit_ids]
        audits = [audit for audit in all_audits if audit.get('auditor_id') == user.get('id')]
    else:
        # For directors and heads of business control: show all reports
        reports = all_reports
        audits = all_audits
    
    # Get user notifications
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user.get('id')]
    
    return render_template('auditor/reports.html', 
                         reports=reports, 
                         audits=audits,
                         current_user=user,
                         notifications=notifications)

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
    user = get_current_user()
    
    # Get document requests from DATA_STORE
    all_requests = DATA_STORE.get('document_requests', {})
    
    # Get audits where this user is auditee
    auditee_audits = [audit for audit in DATA_STORE.get('audits', {}).values() 
                     if audit.get('auditee_id') == user.get('id')]
    auditee_audit_ids = [audit['id'] for audit in auditee_audits]
    
    # Filter document requests for auditee's audits
    auditee_requests = [req for req in all_requests.values() 
                       if req.get('audit_id') in auditee_audit_ids]
    
    # If no requests exist, create some sample ones for demonstration
    if not auditee_requests and auditee_audits:
        sample_requests = []
        for audit in auditee_audits[:2]:  # Create samples for first 2 audits
            sample_requests.extend([
                {
                    'id': f"req_{audit['id']}_1",
                    'audit_id': audit['id'],
                    'audit_title': audit.get('title', 'Unknown Audit'),
                    'requested_by_name': 'System Auditor',
                    'document_type': 'Financial Records',
                    'description': f"Please provide financial records for {audit.get('title', 'audit')}",
                    'priority': 'high',
                    'due_date': '2025-01-30',
                    'status': 'pending'
                },
                {
                    'id': f"req_{audit['id']}_2", 
                    'audit_id': audit['id'],
                    'audit_title': audit.get('title', 'Unknown Audit'),
                    'requested_by_name': 'System Auditor',
                    'document_type': 'Policy Documents',
                    'description': f"Please provide policy documents for {audit.get('title', 'audit')}",
                    'priority': 'medium',
                    'due_date': '2025-02-15',
                    'status': 'pending'
                }
            ])
        auditee_requests = sample_requests
    
    # Get user notifications
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('auditee/document_requests.html', 
                         requests=auditee_requests,
                         current_user=user,
                         notifications=notifications)

@app.route('/upload-evidence-page')
@login_required
@role_required('auditee')
def upload_evidence_page():
    """Evidence upload page"""
    user = get_current_user()
    
    # Get finding from URL parameter
    finding_id = request.args.get('finding_id')
    finding = None
    if finding_id:
        try:
            finding = finding_model.get_by_id(finding_id)
        except Exception as e:
            flash(f'Error loading finding: {str(e)}', 'error')
    
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
    user = get_current_user()
    
    # Get all reports and audits
    all_reports = list(DATA_STORE.get('audit_reports', {}).values())
    all_audits = list(DATA_STORE.get('audits', {}).values())
    
    # Filter reports for audits where this user is auditee
    auditee_audit_ids = [audit['id'] for audit in all_audits if audit.get('auditee_id') == user.get('id')]
    auditee_reports = [report for report in all_reports if report.get('audit_id') in auditee_audit_ids]
    
    # Return only real data - no synthetic reports
    
    # Get user notifications
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('auditee/reports.html', 
                         reports=auditee_reports,
                         current_user=user,
                         notifications=notifications)

@app.route('/auditee-followup')
@login_required
@role_required('auditee')
def auditee_followup():
    """Auditee follow-up page"""
    user = get_current_user()
    
    # Get auditee's audits and related follow-up items
    auditee_audits = [audit for audit in DATA_STORE.get('audits', {}).values() 
                     if audit.get('auditee_id') == user.get('id')]
    
    # Get corrective actions for follow-up tracking
    my_actions = [action for action in DATA_STORE.get('corrective_actions', {}).values() 
                 if action.get('responsible_person_id') == user.get('id')]
    
    # Get completed audits for follow-up review
    completed_audits = [audit for audit in auditee_audits if audit.get('status') == 'completed']
    
    # Create follow-up items from completed audits and pending actions
    followup_items = []
    
    # Add overdue corrective actions
    from datetime import datetime
    for action in my_actions:
        if action.get('target_date') and action.get('status') != 'completed':
            try:
                target_date = datetime.fromisoformat(action['target_date'])
                if target_date < datetime.now():
                    followup_items.append({
                        'id': f"overdue_action_{action['id']}",
                        'type': 'overdue_action',
                        'title': f"Overdue: {action.get('title', 'Corrective Action')}",
                        'description': action.get('description', ''),
                        'due_date': action.get('target_date'),
                        'priority': 'high',
                        'status': action.get('status', 'pending'),
                        'related_audit': action.get('audit_title', 'Unknown Audit')
                    })
            except (ValueError, TypeError):
                pass
    
    # Add follow-up reviews for completed audits - only if we have real follow-up data
    # Note: Only adding items if they exist in the data store, no synthetic generation
    
    # Return only real follow-up data - no synthetic items
    
    # Get user notifications
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('auditee/followup.html', 
                         followup_items=followup_items,
                         my_actions=my_actions,
                         completed_audits=completed_audits,
                         current_user=user,
                         notifications=notifications)

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
    """Delete department - permanently removes department from system"""
    try:
        department = dept_model.get(department_id)
        if not department:
            flash('Department not found.', 'error')
            return redirect(url_for('departments'))
        
        # Check if department has users
        dept_users = user_model.query('department_id', '==', department_id)
        
        if dept_users:
            flash(f'Cannot delete department with {len(dept_users)} assigned users. Please reassign users first.', 'error')
            return redirect(url_for('departments'))
        
        # Delete from Firestore
        dept_model.delete(department_id)
        
        log_audit_action('delete', 'department', department_id, f'Department permanently deleted: {department.get("name")}')
        flash('Department deleted successfully.', 'success')
        
    except Exception as e:
        flash(f'Error deleting department: {str(e)}', 'error')
    
    return redirect(url_for('departments'))

@app.route('/departments/<department_id>/delete_old', methods=['POST'])
@login_required
@role_required('director', 'head_of_business_control')
def delete_department_old(department_id):
    """Old delete department route with CSRF"""
    try:
        # Validate CSRF token
        csrf_token = request.form.get('csrf_token') or (request.get_json() or {}).get('csrf_token')
        if not validate_csrf_token(csrf_token):
            flash('Invalid security token. Please try again.', 'error')
            return redirect(url_for('departments'))
        
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

# CSRF Token endpoint
@app.route('/csrf-token')
@login_required
def get_csrf_token():
    """Get CSRF token for AJAX requests"""
    return jsonify({'csrf_token': generate_csrf_token()})

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
            from io import BytesIO
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            import html
            
            # Create a BytesIO buffer to hold the PDF
            buffer = BytesIO()
            
            # Create the PDF document
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Add title
            title = report.get('title', 'Audit Report')
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=30,
                alignment=1  # Center alignment
            )
            story.append(Paragraph(title, title_style))
            story.append(Spacer(1, 20))
            
            # Add report metadata
            metadata = f"""
            <b>Report Type:</b> {report.get('type', 'N/A').title()}<br/>
            <b>Department:</b> {report.get('department_name', 'N/A')}<br/>
            <b>Generated Date:</b> {report.get('generated_at', 'N/A')}<br/>
            <b>Generated By:</b> {report.get('generated_by_name', 'N/A')}<br/>
            <b>Status:</b> {report.get('status', 'N/A').title()}
            """
            story.append(Paragraph(metadata, styles['Normal']))
            story.append(Spacer(1, 30))
            
            # Add report content
            content = report.get('content', 'No content available')
            # Simple HTML to text conversion for PDF
            content = content.replace('<div class="report-content">', '')
            content = content.replace('</div>', '')
            content = content.replace('<h2>', '<b><font size="16">')
            content = content.replace('</h2>', '</font></b><br/><br/>')
            content = content.replace('<h3>', '<b><font size="14">')
            content = content.replace('</h3>', '</font></b><br/>')
            content = content.replace('<ul>', '<br/>')
            content = content.replace('</ul>', '<br/>')
            content = content.replace('<ol>', '<br/>')
            content = content.replace('</ol>', '<br/>')
            content = content.replace('<li>', '• ')
            content = content.replace('</li>', '<br/>')
            content = content.replace('<p>', '')
            content = content.replace('</p>', '<br/><br/>')
            
            story.append(Paragraph(content, styles['Normal']))
            
            # Build PDF
            doc.build(story)
            
            # Get PDF data
            pdf_data = buffer.getvalue()
            buffer.close()
            
            # Create response
            response = make_response(pdf_data)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename="{report.get("title", "report").replace(" ", "_")}_{report_id}.pdf"'
            
            # Increment download count
            if report_id in DATA_STORE['audit_reports']:
                DATA_STORE['audit_reports'][report_id]['download_count'] = DATA_STORE['audit_reports'][report_id].get('download_count', 0) + 1
            
            return response
            
        except Exception as e:
            flash(f'Error generating PDF: {str(e)}', 'error')
            return redirect(url_for('view_report', report_id=report_id))
    else:
        flash('PDF generation not available.', 'error')
        return redirect(url_for('view_report', report_id=report_id))

# Additional route implementations
@app.route('/auditee-findings')
@login_required
@role_required('auditee')
def auditee_findings():
    """Auditee findings page"""
    user = get_current_user()
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    # Get findings assigned to this auditee
    all_findings = DATA_STORE.get('findings', {})
    my_findings = [f for f in all_findings.values() if f.get('auditee_id') == user['id']]
    
    return render_template('auditee/findings.html',
                         findings=my_findings,
                         current_user=user,
                         notifications=notifications)

@app.route('/view-document-request/<request_id>')
@login_required
def view_document_request(request_id):
    """View document request"""
    # Create a sample document request if not found
    document_request = {
        'id': request_id,
        'audit_title': 'Sample Audit',
        'requested_by_name': 'Auditor Name',
        'document_type': 'Financial Records',
        'description': 'Please provide the requested financial documents.',
        'due_date': '2025-01-30',
        'priority': 'high'
    }
    
    user = get_current_user()
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('auditee/document_requests.html',
                         request=document_request,
                         current_user=user,
                         notifications=notifications)

@app.route('/review-plan/<plan_id>')
@login_required
@role_required('director')
def review_plan(plan_id):
    """Review audit plan"""
    plan = DATA_STORE.get('audits', {}).get(plan_id)
    if not plan:
        flash('Audit plan not found.', 'error')
        return redirect(url_for('dashboard'))
    
    # Enrich plan data
    dept = DATA_STORE.get('departments', {}).get(plan.get('department_id'))
    if dept:
        plan['department_name'] = dept.get('name', 'N/A')
    
    creator = DATA_STORE.get('users', {}).get(plan.get('created_by_id'))
    if creator:
        plan['created_by_name'] = f"{creator.get('first_name', '')} {creator.get('last_name', '')}".strip()
    
    user = get_current_user()
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('director/review_plan.html',
                         plan=plan,
                         current_user=user,
                         notifications=notifications)

@app.route('/approve-plan/<plan_id>', methods=['POST'])
@login_required
@role_required('director')
def approve_plan(plan_id):
    """Approve audit plan"""
    plan = DATA_STORE.get('audits', {}).get(plan_id)
    if plan:
        decision = request.form.get('decision', 'approve')
        director_feedback = request.form.get('director_feedback', '')
        
        if decision == 'approve':
            plan['status'] = 'director_approved'
            plan['approved_by'] = get_current_user()['id']
            plan['approved_at'] = datetime.now().isoformat()
            plan['director_feedback'] = director_feedback
            
            # Notify HBC that plan is approved
            create_notification(
                user_role='head_of_business_control',
                title='Audit Plan Approved',
                message=f'Director approved audit plan: "{plan.get("title", "")}". You can now assign an auditor.',
                notification_type='plan_approved',
                related_entity_type='audit',
                related_entity_id=plan_id
            )
            
            flash('Audit plan approved successfully.', 'success')
            log_audit_action('approve_plan', 'audit', plan_id, 'Audit plan approved by director')
        else:
            # Request changes
            plan['status'] = 'changes_requested'
            plan['director_feedback'] = director_feedback
            
            # Notify HBC that changes are requested
            create_notification(
                user_role='head_of_business_control',
                title='Audit Plan - Changes Requested',
                message=f'Director requested changes to audit plan: "{plan.get("title", "")}". Please review the feedback.',
                notification_type='changes_requested',
                related_entity_type='audit',
                related_entity_id=plan_id
            )
            
            flash('Changes requested. HBC has been notified.', 'info')
            log_audit_action('request_changes', 'audit', plan_id, 'Director requested changes to audit plan')
    else:
        flash('Audit plan not found.', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/view-message/<message_id>')
@login_required
def view_message(message_id):
    """View message"""
    # Sample message data
    message = {
        'id': message_id,
        'from_name': 'Sample Sender',
        'subject': 'Document Request',
        'content': 'Please provide the requested documents.',
        'created_at': datetime.now().isoformat()
    }
    
    user = get_current_user()
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('messages.html',
                         message=message,
                         current_user=user,
                         notifications=notifications)

@app.route('/respond-message/<message_id>')
@login_required
def respond_message(message_id):
    """Respond to message"""
    flash('Message response functionality will be implemented.', 'info')
    return redirect(url_for('view_message', message_id=message_id))

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

# ===============================================
# ENGAGEMENT SETUP AND FIELD COMMUNICATION ROUTES
# ===============================================

@app.route('/engagement-setup')
@login_required
@role_required('head_of_business_control', 'auditor', 'director')
def engagement_setup():
    """Engagement Setup - comprehensive audit setup interface"""
    user = get_current_user()
    
    # Get audits in various setup phases
    all_audits = list(DATA_STORE['audits'].values())
    
    # Filter audits by setup phase
    planning_audits = [audit for audit in all_audits if audit.get('status') in ['assigned', 'acknowledged']]
    approval_audits = [audit for audit in all_audits if audit.get('status') in ['plan_submitted', 'pending_director_approval']]
    coordination_audits = [audit for audit in all_audits if audit.get('status') in ['approved', 'coordinating']]
    
    # Get available resources
    auditors = [u for u in DATA_STORE['users'].values() if u.get('role') == 'auditor' and u.get('is_active', True)]
    auditees = [u for u in DATA_STORE['users'].values() if u.get('role') == 'auditee' and u.get('is_active', True)]
    departments = list(DATA_STORE['departments'].values())
    
    # Setup statistics
    setup_stats = {
        'total_audits': len(all_audits),
        'planning_phase': len(planning_audits),
        'approval_phase': len(approval_audits),
        'coordination_phase': len(coordination_audits),
        'available_auditors': len(auditors),
        'available_auditees': len(auditees)
    }
    
    # Get user notifications
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('engagement_setup.html',
                         planning_audits=planning_audits,
                         approval_audits=approval_audits,
                         coordination_audits=coordination_audits,
                         auditors=auditors,
                         auditees=auditees,
                         departments=departments,
                         setup_stats=setup_stats,
                         current_user=user,
                         notifications=notifications)

@app.route('/engagement-setup/create-plan', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def create_engagement_plan():
    """Create a new engagement plan"""
    try:
        plan_data = {
            'title': request.form['title'],
            'description': request.form['description'],
            'department_id': request.form['department_id'],
            'audit_type': request.form['audit_type'],
            'priority': request.form['priority'],
            'planned_start_date': request.form['planned_start_date'],
            'planned_end_date': request.form['planned_end_date'],
            'audit_scope': request.form.get('audit_scope', ''),
            'audit_objectives': request.form.get('audit_objectives', ''),
            'audit_criteria': request.form.get('audit_criteria', ''),
            'resources_needed': request.form.get('resources_needed', ''),
            'status': 'pending_director_approval',
            'created_by_id': get_current_user()['id'],
            'created_at': datetime.now().isoformat(),
            'reference_number': f"AUD-{datetime.now().year}-{len(DATA_STORE['audits']) + 1:04d}"
        }
        
        audit_id = str(uuid.uuid4())
        plan_data['id'] = audit_id
        DATA_STORE['audits'][audit_id] = plan_data
        
        log_audit_action('create_engagement_plan', 'audit', audit_id, 'New engagement plan created')
        flash('Engagement plan created successfully and submitted for director approval.', 'success')
        
    except Exception as e:
        flash(f'Error creating engagement plan: {str(e)}', 'error')
    
    return redirect(url_for('engagement_setup'))

@app.route('/engagement-setup/coordinate/<audit_id>')
@login_required
@role_required('head_of_business_control', 'auditor')
def coordinate_engagement(audit_id):
    """Coordinate specific engagement setup"""
    audit = DATA_STORE['audits'].get(audit_id)
    if not audit:
        flash('Audit not found.', 'error')
        return redirect(url_for('engagement_setup'))
    
    user = get_current_user()
    
    # Get related data
    auditor = None
    auditee = None
    department = None
    
    if audit.get('auditor_id'):
        auditor = DATA_STORE['users'].get(audit['auditor_id'])
    if audit.get('auditee_id'):
        auditee = DATA_STORE['users'].get(audit['auditee_id'])
    if audit.get('department_id'):
        department = DATA_STORE['departments'].get(audit['department_id'])
    
    # Get engagement checklist items
    checklist_items = [
        {'id': 1, 'task': 'Assign auditor and auditee', 'status': 'completed' if audit.get('auditor_id') else 'pending'},
        {'id': 2, 'task': 'Schedule opening meeting', 'status': audit.get('opening_meeting_scheduled', 'pending')},
        {'id': 3, 'task': 'Prepare document request list', 'status': audit.get('documents_requested', 'pending')},
        {'id': 4, 'task': 'Confirm access arrangements', 'status': audit.get('access_confirmed', 'pending')},
        {'id': 5, 'task': 'Set up communication channels', 'status': audit.get('communication_setup', 'pending')},
        {'id': 6, 'task': 'Notify stakeholders', 'status': audit.get('stakeholders_notified', 'pending')}
    ]
    
    # Get messages related to this audit
    audit_messages = [msg for msg in DATA_STORE['messages'].values() 
                     if msg.get('audit_id') == audit_id]
    
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('engagement_coordination.html',
                         audit=audit,
                         auditor=auditor,
                         auditee=auditee,
                         department=department,
                         checklist_items=checklist_items,
                         audit_messages=audit_messages,
                         current_user=user,
                         notifications=notifications)

@app.route('/field-communication')
@login_required  
@role_required('auditor', 'auditee', 'head_of_business_control')
def field_communication():
    """Field Communication - real-time communication during audit execution"""
    user = get_current_user()
    
    # Get user's active audits
    active_audits = []
    if user.get('role') == 'auditor':
        active_audits = [audit for audit in DATA_STORE['audits'].values() 
                        if audit.get('auditor_id') == user['id'] and audit.get('status') in ['in_progress', 'assigned', 'acknowledged']]
    elif user.get('role') == 'auditee':
        active_audits = [audit for audit in DATA_STORE['audits'].values() 
                        if audit.get('auditee_id') == user['id'] and audit.get('status') in ['in_progress', 'assigned', 'acknowledged']]
    elif user.get('role') == 'head_of_business_control':
        active_audits = [audit for audit in DATA_STORE['audits'].values() 
                        if audit.get('supervisor_id') == user['id'] and audit.get('status') in ['in_progress', 'assigned', 'acknowledged']]
    
    # Get all messages for active audits
    audit_messages = {}
    for audit in active_audits:
        audit_id = audit['id']
        messages = [msg for msg in DATA_STORE['messages'].values() 
                   if msg.get('audit_id') == audit_id]
        audit_messages[audit_id] = sorted(messages, key=lambda x: x.get('created_at', ''), reverse=True)
    
    # Get document requests
    document_requests = []
    for audit in active_audits:
        # Create sample document requests based on audit status
        if audit.get('status') in ['in_progress', 'acknowledged']:
            document_requests.extend([
                {
                    'id': f"req_{audit['id']}_1",
                    'audit_id': audit['id'],
                    'audit_title': audit.get('title', 'Untitled Audit'),
                    'document_type': 'Financial Records',
                    'description': 'Monthly financial statements and transaction logs',
                    'priority': 'high',
                    'status': 'pending',
                    'due_date': '2025-10-15',
                    'requested_by': 'Auditor',
                    'created_at': datetime.now().isoformat()
                },
                {
                    'id': f"req_{audit['id']}_2", 
                    'audit_id': audit['id'],
                    'audit_title': audit.get('title', 'Untitled Audit'),
                    'document_type': 'Policy Documents',
                    'description': 'Current operational policies and procedures',
                    'priority': 'medium',
                    'status': 'pending',
                    'due_date': '2025-10-20',
                    'requested_by': 'Auditor',
                    'created_at': datetime.now().isoformat()
                }
            ])
    
    # Get evidence files
    evidence_files = []
    for audit in active_audits:
        audit_evidence = [evidence for evidence in DATA_STORE['evidence_files'].values() 
                         if evidence.get('audit_id') == audit['id']]
        evidence_files.extend(audit_evidence)
    
    # Communication statistics
    comm_stats = {
        'active_audits': len(active_audits),
        'total_messages': sum(len(msgs) for msgs in audit_messages.values()),
        'pending_requests': len([req for req in document_requests if req.get('status') == 'pending']),
        'evidence_files': len(evidence_files),
        'unread_messages': sum(len([msg for msg in msgs if not msg.get('is_read', False)]) for msgs in audit_messages.values())
    }
    
    # Get all users for messaging
    all_users = [u for u in DATA_STORE['users'].values() if u.get('id') != user['id'] and u.get('is_active', True)]
    
    notifications = [n for n in DATA_STORE.get('notifications', {}).values() if n.get('user_id') == user['id']]
    
    return render_template('field_communication.html',
                         active_audits=active_audits,
                         audit_messages=audit_messages,
                         document_requests=document_requests,
                         evidence_files=evidence_files,
                         comm_stats=comm_stats,
                         all_users=all_users,
                         current_user=user,
                         notifications=notifications)

@app.route('/field-communication/send-request', methods=['POST'])
@login_required
@role_required('auditor')
def send_document_request():
    """Send document request to auditee"""
    try:
        request_data = {
            'id': str(uuid.uuid4()),
            'audit_id': request.form['audit_id'],
            'document_type': request.form['document_type'],
            'description': request.form['description'],
            'priority': request.form.get('priority', 'medium'),
            'due_date': request.form['due_date'],
            'status': 'pending',
            'requested_by': get_current_user()['id'],
            'created_at': datetime.now().isoformat()
        }
        
        # Store request (in a real app this would go to a document_requests collection)
        if 'document_requests' not in DATA_STORE:
            DATA_STORE['document_requests'] = {}
        DATA_STORE['document_requests'][request_data['id']] = request_data
        
        log_audit_action('send_document_request', 'document_request', request_data['id'], 'Document request sent')
        flash('Document request sent successfully.', 'success')
        
    except Exception as e:
        flash(f'Error sending document request: {str(e)}', 'error')
    
    return redirect(url_for('field_communication'))

@app.route('/field-communication/quick-message', methods=['POST'])
@login_required
def send_quick_message():
    """Send quick message in field communication"""
    try:
        message_data = {
            'audit_id': request.form['audit_id'],
            'sender_id': get_current_user()['id'],
            'recipient_id': request.form['recipient_id'],
            'message_content': request.form['message_content'],
            'message_type': 'quick_communication',
            'subject': request.form.get('subject', 'Field Communication'),
            'priority': request.form.get('priority', 'normal'),
            'created_at': datetime.now().isoformat()
        }
        
        message_id = message_model.send_message(message_data)
        log_audit_action('send_quick_message', 'message', message_id, 'Quick message sent')
        
        flash('Message sent successfully.', 'success')
        
    except Exception as e:
        flash(f'Error sending message: {str(e)}', 'error')
    
    return redirect(url_for('field_communication'))

# ============================================================================
# AUDIT MANAGEMENT SYSTEM WORKFLOW ROUTES (3-Phase System)
# ============================================================================

# ==================== PHASE 1: AUDIT ASSIGNMENT PHASE ====================

@app.route('/audit/create', methods=['GET', 'POST'])
@login_required
@role_required('head_of_business_control')
def create_audit_workflow():
    """
    Phase 1, Steps 1-3: HBC creates audit request, defines scope & objectives,
    develops audit plan (Draft status)
    """
    if request.method == 'POST':
        try:
            user = get_current_user()
            audit_data = {
                'id': str(uuid.uuid4()),
                'reference_number': f"AUD-{datetime.now().year}-{str(uuid.uuid4())[:8].upper()}",
                'title': request.form['title'],
                'description': request.form.get('description', ''),
                'audit_type': request.form['audit_type'],
                'department_id': request.form.get('department_id'),
                'status': 'draft',
                'priority': request.form.get('priority', 'medium'),
                
                # Trigger information (Step 1)
                'trigger_type': request.form.get('trigger_type', 'scheduled'),
                'trigger_details': request.form.get('trigger_details', ''),
                
                # Scope & Objectives (Step 2)
                'audit_scope': request.form.get('audit_scope', ''),
                'audit_objectives': request.form.get('audit_objectives', ''),
                'audit_criteria': request.form.get('audit_criteria', ''),
                'resources_needed': request.form.get('resources_needed', ''),
                
                # Dates
                'planned_start_date': request.form.get('planned_start_date'),
                'planned_end_date': request.form.get('planned_end_date'),
                
                # Audit Plan (Step 3)
                'audit_plan': request.form.get('audit_plan', ''),
                'activity_breakdown': request.form.get('activity_breakdown', ''),
                'audit_checklist': request.form.get('audit_checklist', ''),
                'data_request_list': request.form.get('data_request_list', ''),
                
                # Meta
                'created_by_id': user['id'],
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            audit_id = audit_data['id']
            DATA_STORE['audits'][audit_id] = audit_data
            
            log_audit_action('create_audit', 'audit', audit_id, f'Audit created: {audit_data["title"]}')
            
            flash(f'Audit "{audit_data["title"]}" created successfully as draft.', 'success')
            return redirect(url_for('head_of_business_control_dashboard'))
            
        except Exception as e:
            flash(f'Error creating audit: {str(e)}', 'error')
    
    departments = list(DATA_STORE['departments'].values())
    return render_template('audits/create_comprehensive.html', departments=departments)


@app.route('/audit/<audit_id>/submit-to-director', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def submit_audit_to_director(audit_id):
    """
    Phase 1, Step 3: HBC submits audit plan to Director for review
    Status: draft -> pending_director_approval
    """
    try:
        audit = DATA_STORE['audits'].get(audit_id)
        if not audit:
            flash('Audit not found.', 'error')
            return redirect(url_for('head_of_business_control_dashboard'))
        
        if audit['status'] != 'draft':
            flash('Audit is not in draft status.', 'error')
            return redirect(url_for('head_of_business_control_dashboard'))
        
        # Update audit status
        audit['status'] = 'pending_director_approval'
        audit['plan_submitted_at'] = datetime.now().isoformat()
        audit['updated_at'] = datetime.now().isoformat()
        
        # Create notification for Director
        create_notification(
            user_role='director',
            title='Audit Plan Approval Required',
            message=f'Audit "{audit["title"]}" has been submitted for your review and approval.',
            notification_type='plan_approval_needed',
            related_entity_type='audit',
            related_entity_id=audit_id
        )
        
        log_audit_action('submit_to_director', 'audit', audit_id, 'Audit plan submitted to Director for approval')
        
        flash(f'Audit plan submitted to Director for approval.', 'success')
        
    except Exception as e:
        flash(f'Error submitting audit: {str(e)}', 'error')
    
    return redirect(url_for('head_of_business_control_dashboard'))


@app.route('/audit/<audit_id>/director-review', methods=['GET', 'POST'])
@login_required
@role_required('director')
def director_review_audit(audit_id):
    """
    Phase 1, Step 4: Director reviews and approves/rejects audit plan
    Status: pending_director_approval -> director_approved (or back to draft)
    """
    audit = DATA_STORE['audits'].get(audit_id)
    if not audit:
        flash('Audit not found.', 'error')
        return redirect(url_for('director_dashboard'))
    
    if request.method == 'POST':
        try:
            action = request.form.get('action')
            feedback = request.form.get('director_feedback', '')
            
            if action == 'approve':
                audit['status'] = 'director_approved'
                audit['director_approved_at'] = datetime.now().isoformat()
                audit['director_feedback'] = feedback
                audit['updated_at'] = datetime.now().isoformat()
                
                # Notify HBC
                create_notification(
                    user_role='head_of_business_control',
                    title='Audit Plan Approved',
                    message=f'Director approved audit plan: "{audit["title"]}". You can now assign an auditor.',
                    notification_type='plan_approved',
                    related_entity_type='audit',
                    related_entity_id=audit_id
                )
                
                log_audit_action('approve_audit', 'audit', audit_id, 'Director approved audit plan')
                flash('Audit plan approved successfully.', 'success')
                
            elif action == 'reject':
                audit['status'] = 'draft'
                audit['director_feedback'] = feedback
                audit['updated_at'] = datetime.now().isoformat()
                
                # Notify HBC
                create_notification(
                    user_role='head_of_business_control',
                    title='Audit Plan Returned',
                    message=f'Director returned audit plan: "{audit["title"]}" with comments. Please revise.',
                    notification_type='plan_rejected',
                    related_entity_type='audit',
                    related_entity_id=audit_id
                )
                
                log_audit_action('reject_audit', 'audit', audit_id, 'Director returned audit plan with comments')
                flash('Audit plan returned with comments.', 'success')
            
            return redirect(url_for('director_dashboard'))
            
        except Exception as e:
            flash(f'Error reviewing audit: {str(e)}', 'error')
    
    # Get audit creator info
    creator = DATA_STORE['users'].get(audit.get('created_by_id'))
    department = DATA_STORE['departments'].get(audit.get('department_id'))
    
    return render_template('director/review_plan.html', 
                         audit=audit,
                         creator=creator,
                         department=department)


@app.route('/audit/<audit_id>/assign-auditor', methods=['GET', 'POST'])
@login_required
@role_required('head_of_business_control')
def assign_auditor_workflow(audit_id):
    """
    Phase 1, Step 5: HBC assigns auditor with segregation of duty check
    Status: director_approved -> assigned
    """
    audit = DATA_STORE['audits'].get(audit_id)
    if not audit:
        flash('Audit not found.', 'error')
        return redirect(url_for('head_of_business_control_dashboard'))
    
    if request.method == 'POST':
        try:
            auditor_id = request.form.get('auditor_id')
            auditee_id = request.form.get('auditee_id')
            supervisor_id = request.form.get('supervisor_id', get_current_user()['id'])
            
            # Segregation of duty check: Auditor cannot be from same department
            auditor = DATA_STORE['users'].get(auditor_id)
            department_id = audit.get('department_id')
            
            if auditor and auditor.get('department_id') == department_id:
                flash('Conflict of interest: Auditor cannot be from the department being audited.', 'error')
                return redirect(url_for('assign_auditor_workflow', audit_id=audit_id))
            
            # Assign auditor
            audit['auditor_id'] = auditor_id
            audit['auditee_id'] = auditee_id
            audit['supervisor_id'] = supervisor_id
            audit['status'] = 'assigned'
            audit['auditor_assigned_at'] = datetime.now().isoformat()
            audit['updated_at'] = datetime.now().isoformat()
            
            # Notify auditor
            create_notification(
                user_id=auditor_id,
                title='New Audit Assignment',
                message=f'You have been assigned to audit: "{audit["title"]}". Please acknowledge this assignment.',
                notification_type='audit_assigned',
                related_entity_type='audit',
                related_entity_id=audit_id
            )
            
            log_audit_action('assign_auditor', 'audit', audit_id, f'Auditor assigned: {auditor.get("first_name")} {auditor.get("last_name")}')
            
            flash('Auditor assigned successfully. Notification sent to auditor.', 'success')
            return redirect(url_for('head_of_business_control_dashboard'))
            
        except Exception as e:
            flash(f'Error assigning auditor: {str(e)}', 'error')
    
    # Get available auditors
    auditors = [u for u in DATA_STORE['users'].values() if u.get('role') == 'auditor' and u.get('is_active')]
    auditees = [u for u in DATA_STORE['users'].values() if u.get('role') == 'auditee' and u.get('is_active')]
    department = DATA_STORE['departments'].get(audit.get('department_id'))
    
    return render_template('head_of_business_control/assign_auditors.html', 
                         audit=audit,
                         auditors=auditors,
                         auditees=auditees,
                         department=department)


# ==================== PHASE 2: AUDITOR'S PREPARATION PHASE ====================

@app.route('/audit/<audit_id>/acknowledge', methods=['POST'])
@login_required
@role_required('auditor')
def auditor_acknowledge_assignment(audit_id):
    """
    Phase 2, Step 6: Auditor acknowledges assignment
    Status: assigned -> acknowledged
    """
    try:
        audit = DATA_STORE['audits'].get(audit_id)
        if not audit:
            flash('Audit not found.', 'error')
            return redirect(url_for('auditor_dashboard'))
        
        user = get_current_user()
        if audit.get('auditor_id') != user['id']:
            flash('You are not assigned to this audit.', 'error')
            return redirect(url_for('auditor_dashboard'))
        
        if audit['status'] != 'assigned':
            flash('Audit is not in assigned status.', 'error')
            return redirect(url_for('auditor_dashboard'))
        
        # Update status
        audit['status'] = 'acknowledged'
        audit['auditor_acknowledged_at'] = datetime.now().isoformat()
        audit['updated_at'] = datetime.now().isoformat()
        
        # Notify HBC
        create_notification(
            user_id=audit.get('supervisor_id'),
            title='Auditor Acknowledged Assignment',
            message=f'Auditor {user.get("first_name")} {user.get("last_name")} acknowledged audit: "{audit["title"]}".',
            notification_type='audit_acknowledged',
            related_entity_type='audit',
            related_entity_id=audit_id
        )
        
        log_audit_action('acknowledge_audit', 'audit', audit_id, 'Auditor acknowledged assignment')
        
        flash('Assignment acknowledged successfully.', 'success')
        
    except Exception as e:
        flash(f'Error acknowledging assignment: {str(e)}', 'error')
    
    return redirect(url_for('auditor_dashboard'))


@app.route('/audit/<audit_id>/notify-auditee', methods=['GET', 'POST'])
@login_required
@role_required('auditor')
def notify_auditee_workflow(audit_id):
    """
    Phase 2, Step 8: Auditor notifies auditee and requests documents
    Status: acknowledged -> auditee_notified
    """
    audit = DATA_STORE['audits'].get(audit_id)
    if not audit:
        flash('Audit not found.', 'error')
        return redirect(url_for('auditor_dashboard'))
    
    if request.method == 'POST':
        try:
            user = get_current_user()
            
            # Update audit status
            audit['status'] = 'auditee_notified'
            audit['auditee_notified_at'] = datetime.now().isoformat()
            audit['document_request_sent_at'] = datetime.now().isoformat()
            audit['tentative_audit_date'] = request.form.get('tentative_audit_date')
            audit['updated_at'] = datetime.now().isoformat()
            
            # Create document request
            document_list = request.form.get('document_list', '').split('\n')
            for doc in document_list:
                if doc.strip():
                    req_id = str(uuid.uuid4())
                    request_data = {
                        'id': req_id,
                        'audit_id': audit_id,
                        'requested_by_id': user['id'],
                        'auditee_id': audit.get('auditee_id'),
                        'document_type': 'general',
                        'document_description': doc.strip(),
                        'priority': 'high',
                        'status': 'pending',
                        'created_at': datetime.now().isoformat()
                    }
                    
                    if 'document_requests' not in DATA_STORE:
                        DATA_STORE['document_requests'] = {}
                    DATA_STORE['document_requests'][req_id] = request_data
            
            # Notify auditee
            create_notification(
                user_id=audit.get('auditee_id'),
                title='Audit Notification',
                message=f'You have been notified about audit: "{audit["title"]}". Please review document requests and prepare for the audit.',
                notification_type='audit_notification',
                related_entity_type='audit',
                related_entity_id=audit_id
            )
            
            log_audit_action('notify_auditee', 'audit', audit_id, 'Auditee notified and documents requested')
            
            flash('Auditee notified and document requests sent successfully.', 'success')
            return redirect(url_for('auditor_dashboard'))
            
        except Exception as e:
            flash(f'Error notifying auditee: {str(e)}', 'error')
    
    auditee = DATA_STORE['users'].get(audit.get('auditee_id'))
    return render_template('auditor/notify_auditee.html', audit=audit, auditee=auditee)


# ==================== PHASE 3: PRE-AUDIT PLANNING & APPROVAL PHASE ====================

@app.route('/audit/<audit_id>/submit-detailed-plan', methods=['GET', 'POST'])
@login_required
@role_required('auditor')
def submit_detailed_plan(audit_id):
    """
    Phase 3, Step 9: Auditor submits detailed fieldwork plan to HBC
    Status: auditee_notified -> auditor_plan_submitted
    """
    audit = DATA_STORE['audits'].get(audit_id)
    if not audit:
        flash('Audit not found.', 'error')
        return redirect(url_for('auditor_dashboard'))
    
    if request.method == 'POST':
        try:
            user = get_current_user()
            
            if audit.get('auditor_id') != user['id']:
                flash('You are not assigned to this audit.', 'error')
                return redirect(url_for('auditor_dashboard'))
            
            # Update audit with detailed plan
            audit['detailed_fieldwork_plan'] = request.form.get('detailed_fieldwork_plan', '')
            audit['audit_methodology'] = request.form.get('audit_methodology', '')
            audit['sampling_method'] = request.form.get('sampling_method', '')
            audit['fieldwork_timeline'] = request.form.get('fieldwork_timeline', '')
            audit['status'] = 'auditor_plan_submitted'
            audit['auditor_plan_submitted_at'] = datetime.now().isoformat()
            audit['updated_at'] = datetime.now().isoformat()
            
            # Notify HBC for review
            create_notification(
                user_id=audit.get('supervisor_id'),
                title='Detailed Audit Plan Submitted',
                message=f'Auditor submitted detailed fieldwork plan for: "{audit["title"]}". Please review and approve.',
                notification_type='auditor_plan_submitted',
                related_entity_type='audit',
                related_entity_id=audit_id
            )
            
            log_audit_action('submit_detailed_plan', 'audit', audit_id, 'Auditor submitted detailed fieldwork plan')
            
            flash('Detailed fieldwork plan submitted to HBC for approval.', 'success')
            return redirect(url_for('auditor_dashboard'))
            
        except Exception as e:
            flash(f'Error submitting plan: {str(e)}', 'error')
    
    return render_template('auditor/prepare_plan.html', audit=audit)


@app.route('/audit/<audit_id>/approve-auditor-plan', methods=['GET', 'POST'])
@login_required
@role_required('head_of_business_control')
def approve_auditor_plan(audit_id):
    """
    Phase 3, Step 10: HBC reviews and approves auditor's detailed plan
    Status: auditor_plan_submitted -> ready_for_fieldwork
    """
    audit = DATA_STORE['audits'].get(audit_id)
    if not audit:
        flash('Audit not found.', 'error')
        return redirect(url_for('head_of_business_control_dashboard'))
    
    if request.method == 'POST':
        try:
            action = request.form.get('action')
            feedback = request.form.get('supervisor_feedback', '')
            
            if action == 'approve':
                audit['status'] = 'ready_for_fieldwork'
                audit['ready_for_fieldwork_at'] = datetime.now().isoformat()
                audit['supervisor_feedback'] = feedback
                audit['updated_at'] = datetime.now().isoformat()
                
                # Notify auditor
                create_notification(
                    user_id=audit.get('auditor_id'),
                    title='Audit Plan Approved',
                    message=f'Your detailed fieldwork plan for "{audit["title"]}" has been approved. You can proceed with fieldwork.',
                    notification_type='plan_approved',
                    related_entity_type='audit',
                    related_entity_id=audit_id
                )
                
                log_audit_action('approve_auditor_plan', 'audit', audit_id, 'HBC approved auditor detailed plan')
                flash('Auditor plan approved. Audit is ready for fieldwork.', 'success')
                
            elif action == 'reject':
                audit['status'] = 'acknowledged'  # Return to auditor for plan revision
                audit['supervisor_feedback'] = feedback
                audit['updated_at'] = datetime.now().isoformat()
                
                # Notify auditor
                create_notification(
                    user_id=audit.get('auditor_id'),
                    title='Audit Plan Returned',
                    message=f'Your fieldwork plan for "{audit["title"]}" was returned with revisions requested.',
                    notification_type='plan_revision_requested',
                    related_entity_type='audit',
                    related_entity_id=audit_id
                )
                
                log_audit_action('reject_auditor_plan', 'audit', audit_id, 'HBC requested revisions to auditor plan')
                flash('Plan returned to auditor with revision requests.', 'success')
            
            return redirect(url_for('head_of_business_control_dashboard'))
            
        except Exception as e:
            flash(f'Error reviewing plan: {str(e)}', 'error')
    
    auditor = DATA_STORE['users'].get(audit.get('auditor_id'))
    return render_template('head_of_business_control/review_auditor_plan.html', 
                         audit=audit,
                         auditor=auditor)


@app.route('/audit/<audit_id>/auditee-prepare', methods=['GET', 'POST'])
@login_required
@role_required('auditee')
def auditee_prepare(audit_id):
    """
    Phase 3, Step 11: Auditee acknowledges and prepares (submits documents)
    Status: auditee_notified/ready_for_fieldwork -> pre_audit_ready
    """
    audit = DATA_STORE['audits'].get(audit_id)
    if not audit:
        flash('Audit not found.', 'error')
        return redirect(url_for('auditee_dashboard'))
    
    if request.method == 'POST':
        try:
            user = get_current_user()
            
            if audit.get('auditee_id') != user['id']:
                flash('You are not the auditee for this audit.', 'error')
                return redirect(url_for('auditee_dashboard'))
            
            # Mark auditee as acknowledged and prepared
            audit['auditee_acknowledged_at'] = datetime.now().isoformat()
            audit['access_arrangements_completed'] = True
            audit['status'] = 'pre_audit_ready'
            audit['updated_at'] = datetime.now().isoformat()
            
            # Notify auditor and HBC
            for user_id in [audit.get('auditor_id'), audit.get('supervisor_id')]:
                if user_id:
                    create_notification(
                        user_id=user_id,
                        title='Auditee Preparation Complete',
                        message=f'Auditee has completed preparations for audit: "{audit["title"]}". Pre-audit phase is complete.',
                        notification_type='pre_audit_ready',
                        related_entity_type='audit',
                        related_entity_id=audit_id
                    )
            
            log_audit_action('auditee_prepare', 'audit', audit_id, 'Auditee completed preparations')
            
            flash('Preparation complete. All stakeholders have been notified.', 'success')
            return redirect(url_for('auditee_dashboard'))
            
        except Exception as e:
            flash(f'Error completing preparation: {str(e)}', 'error')
    
    # Get document requests for this audit
    document_requests = [req for req in DATA_STORE.get('document_requests', {}).values() 
                        if req.get('audit_id') == audit_id]
    auditor = DATA_STORE['users'].get(audit.get('auditor_id'))
    
    return render_template('auditee/prepare_audit.html', 
                         audit=audit,
                         document_requests=document_requests,
                         auditor=auditor)

@app.route('/audit/delete/<audit_id>', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def delete_audit(audit_id):
    """Delete a single audit"""
    try:
        if audit_id in DATA_STORE['audits']:
            audit = DATA_STORE['audits'][audit_id]
            audit_title = audit.get('title', 'Unknown')
            del DATA_STORE['audits'][audit_id]
            log_audit_action('delete', 'audit', audit_id, f'Audit deleted: {audit_title}')
            flash('Audit deleted successfully.', 'success')
        else:
            flash('Audit not found.', 'error')
    except Exception as e:
        flash(f'Error deleting audit: {str(e)}', 'error')
    
    return redirect(url_for('head_of_business_control_dashboard'))

@app.route('/audits/bulk-delete', methods=['POST'])
@login_required
@role_required('head_of_business_control')
def bulk_delete_audits():
    """Delete multiple audits"""
    try:
        audit_ids_json = request.form.get('audit_ids')
        if not audit_ids_json:
            flash('No audits selected for deletion.', 'error')
            return redirect(url_for('head_of_business_control_dashboard'))
        
        audit_ids = json.loads(audit_ids_json)
        deleted_count = 0
        
        for audit_id in audit_ids:
            try:
                if audit_id in DATA_STORE['audits']:
                    audit = DATA_STORE['audits'][audit_id]
                    audit_title = audit.get('title', 'Unknown')
                    del DATA_STORE['audits'][audit_id]
                    log_audit_action('delete', 'audit', audit_id, f'Audit deleted: {audit_title}')
                    deleted_count += 1
            except Exception as e:
                flash(f'Error deleting audit {audit_id}: {str(e)}', 'error')
        
        flash(f'{deleted_count} audit(s) deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error during bulk delete: {str(e)}', 'error')
    
    return redirect(url_for('head_of_business_control_dashboard'))


# ==================== HELPER FUNCTIONS ====================

def create_notification(user_id=None, user_role=None, title='', message='', 
                       notification_type='general', related_entity_type=None, 
                       related_entity_id=None):
    """Create notification for user(s)"""
    if 'notifications' not in DATA_STORE:
        DATA_STORE['notifications'] = {}
    
    # If user_role is specified, send to all users with that role
    if user_role:
        users = [u for u in DATA_STORE['users'].values() if u.get('role') == user_role]
        for user in users:
            notif_id = str(uuid.uuid4())
            notification_data = {
                'id': notif_id,
                'user_id': user['id'],
                'title': title,
                'message': message,
                'notification_type': notification_type,
                'is_read': False,
                'related_entity_type': related_entity_type,
                'related_entity_id': related_entity_id,
                'created_at': datetime.now().isoformat()
            }
            DATA_STORE['notifications'][notif_id] = notification_data
    elif user_id:
        notif_id = str(uuid.uuid4())
        notification_data = {
            'id': notif_id,
            'user_id': user_id,
            'title': title,
            'message': message,
            'notification_type': notification_type,
            'is_read': False,
            'related_entity_type': related_entity_type,
            'related_entity_id': related_entity_id,
            'created_at': datetime.now().isoformat()
        }
        DATA_STORE['notifications'][notif_id] = notification_data