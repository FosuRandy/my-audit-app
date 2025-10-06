"""
Global data store for the audit management system
This provides a centralized in-memory storage that can work with or without Firebase
"""
from datetime import datetime
import uuid

# Global in-memory data store
DATA_STORE = {
    'users': {},
    'departments': {},
    'audits': {},
    'risk_assessments': {},
    'risks': {},  # Alias for risk_assessments for compatibility
    'findings': {},
    'corrective_actions': {},
    'messages': {},
    'evidence_files': {},
    'audit_reports': {},
    'audit_logs': {}
}

def initialize_sample_data():
    """Initialize the system with sample data"""
    
    # Create default admin user
    admin_id = str(uuid.uuid4())
    admin_data = {
        'id': admin_id,
        'email': 'admin@audit.system',
        'role': 'director',
        'first_name': 'System',
        'last_name': 'Administrator',
        'username': 'admin',
        'phone': '+1-555-0001',
        'is_active': True,
        'password_reset_required': False,
        'created_at': datetime.utcnow(),
        'last_login': None
    }
    DATA_STORE['users'][admin_id] = admin_data
    
    # Create sample departments
    dept_ids = []
    departments_data = [
        {'name': 'Internal Audit', 'description': 'Internal audit department'},
        {'name': 'Finance', 'description': 'Finance and accounting department'},
        {'name': 'Operations', 'description': 'Operations department'},
        {'name': 'IT', 'description': 'Information technology department'},
    ]
    
    for dept_data in departments_data:
        dept_id = str(uuid.uuid4())
        dept_data.update({
            'id': dept_id,
            'is_active': True,
            'created_at': datetime.utcnow()
        })
        DATA_STORE['departments'][dept_id] = dept_data
        dept_ids.append(dept_id)
    
    # Create sample users for each role
    sample_users = [
        {
            'email': 'head@audit.system',
            'role': 'head_of_business_control',
            'first_name': 'Business',
            'last_name': 'Control',
            'username': 'head_control',
            'department_id': dept_ids[0] if dept_ids else None
        },
        {
            'email': 'auditor@audit.system',
            'role': 'auditor',
            'first_name': 'John',
            'last_name': 'Auditor',
            'username': 'auditor1',
            'department_id': dept_ids[0] if dept_ids else None
        },
        {
            'email': 'auditee@audit.system',
            'role': 'auditee',
            'first_name': 'Jane',
            'last_name': 'Manager',
            'username': 'auditee1',
            'department_id': dept_ids[1] if dept_ids else None
        }
    ]
    
    for user_data in sample_users:
        user_id = str(uuid.uuid4())
        user_data.update({
            'id': user_id,
            'phone': '+1-555-0000',
            'is_active': True,
            'password_reset_required': True,
            'created_at': datetime.utcnow(),
            'last_login': None
        })
        DATA_STORE['users'][user_id] = user_data
    
    # Create sample audits with workflow statuses
    sample_audits = [
        {
            'title': 'Financial Controls Audit',
            'description': 'Review of financial control processes',
            'audit_type': 'financial',
            'department_id': dept_ids[1] if dept_ids else None,
            'status': 'draft',
            'priority': 'medium',
            'planned_start_date': '2025-02-01',
            'planned_end_date': '2025-02-28'
        },
        {
            'title': 'IT Security Assessment',
            'description': 'Comprehensive security audit of IT systems',
            'audit_type': 'security',
            'department_id': dept_ids[2] if dept_ids else None,
            'status': 'pending_director_approval',
            'priority': 'high',
            'planned_start_date': '2025-01-15',
            'planned_end_date': '2025-02-15'
        },
        {
            'title': 'Compliance Review Q1',
            'description': 'Quarterly compliance review',
            'audit_type': 'compliance',
            'department_id': dept_ids[3] if dept_ids else None,
            'status': 'director_approved',
            'priority': 'medium',
            'planned_start_date': '2025-03-01',
            'planned_end_date': '2025-03-31'
        }
    ]
    
    for audit_data in sample_audits:
        audit_id = str(uuid.uuid4())
        audit_data.update({
            'id': audit_id,
            'reference_number': f'AUD-2025-{str(uuid.uuid4())[:8].upper()}',
            'created_at': datetime.utcnow()
        })
        DATA_STORE['audits'][audit_id] = audit_data
    
    # Create sample risk assessment
    risk_id = str(uuid.uuid4())
    risk_data = {
        'id': risk_id,
        'risk_description': 'Data security vulnerabilities',
        'department_id': dept_ids[2] if dept_ids else None,
        'impact_level': 'high',
        'likelihood_level': 'likely',
        'risk_score': 12,
        'risk_level': 'high',
        'mitigation_measures': 'Implement enhanced security protocols',
        'created_at': datetime.utcnow()
    }
    DATA_STORE['risk_assessments'][risk_id] = risk_data
    # Also add to 'risks' for compatibility
    DATA_STORE['risks'][risk_id] = risk_data
    
    # Create sample reports
    sample_reports = [
        {
            'id': 'sample-1',
            'title': 'Financial Controls Audit Q4 2024',
            'type': 'financial',
            'department_name': 'Finance',
            'generated_at': '2024-12-15',
            'generated_by_name': 'Senior Auditor',
            'status': 'completed',
            'download_count': 23,
            'content': '''
            <div class="report-content">
                <h2>Financial Controls Audit Report - Q4 2024</h2>
                <h3>Executive Summary</h3>
                <p>This comprehensive audit examined the financial controls and processes within the Finance department for Q4 2024.</p>
                
                <h3>Key Findings</h3>
                <ul>
                    <li>Strong internal controls for expense approvals</li>
                    <li>Minor deficiencies in reconciliation procedures</li>
                    <li>Excellent compliance with financial reporting standards</li>
                </ul>
                
                <h3>Recommendations</h3>
                <ol>
                    <li>Implement automated reconciliation tools</li>
                    <li>Enhance monthly closing procedures</li>
                    <li>Provide additional training on new accounting standards</li>
                </ol>
                
                <h3>Management Response</h3>
                <p>Management accepts all recommendations and has committed to implementation by Q2 2025.</p>
            </div>
            '''
        },
        {
            'id': 'sample-2',
            'title': 'IT Security Assessment 2024',
            'type': 'security',
            'department_name': 'IT',
            'generated_at': '2024-11-30',
            'generated_by_name': 'Security Auditor',
            'status': 'completed',
            'download_count': 18,
            'content': '''
            <div class="report-content">
                <h2>IT Security Assessment Report - 2024</h2>
                <h3>Executive Summary</h3>
                <p>Annual security assessment of IT infrastructure, systems, and protocols.</p>
                
                <h3>Security Findings</h3>
                <ul>
                    <li>Network security controls are effective</li>
                    <li>User access management needs improvement</li>
                    <li>Incident response procedures are well-documented</li>
                </ul>
                
                <h3>Risk Assessment</h3>
                <p>Overall security posture is good with some areas requiring attention.</p>
                
                <h3>Action Items</h3>
                <ol>
                    <li>Update user access review procedures</li>
                    <li>Implement multi-factor authentication</li>
                    <li>Conduct quarterly security training</li>
                </ol>
            </div>
            '''
        },
        {
            'id': 'sample-3',
            'title': 'Compliance Review Q3 2024',
            'type': 'compliance',
            'department_name': 'Legal',
            'generated_at': '2024-10-20',
            'generated_by_name': 'Compliance Officer',
            'status': 'completed',
            'download_count': 15,
            'content': '''
            <div class="report-content">
                <h2>Compliance Review Report - Q3 2024</h2>
                <h3>Scope</h3>
                <p>Review of regulatory compliance across all business units for Q3 2024.</p>
                
                <h3>Compliance Status</h3>
                <ul>
                    <li>Full compliance with industry regulations</li>
                    <li>Minor documentation gaps identified</li>
                    <li>Training programs are effective</li>
                </ul>
                
                <h3>Areas for Improvement</h3>
                <ol>
                    <li>Standardize compliance documentation</li>
                    <li>Increase frequency of compliance reviews</li>
                    <li>Update compliance monitoring procedures</li>
                </ol>
            </div>
            '''
        },
        {
            'id': 'sample-4',
            'title': 'Operational Efficiency Review',
            'type': 'operational',
            'department_name': 'Operations',
            'generated_at': '2024-09-15',
            'generated_by_name': 'Operations Auditor',
            'status': 'completed',
            'download_count': 12,
            'content': '''
            <div class="report-content">
                <h2>Operational Efficiency Review</h2>
                <h3>Objective</h3>
                <p>Assess operational efficiency and identify improvement opportunities.</p>
                
                <h3>Key Metrics</h3>
                <ul>
                    <li>Process efficiency increased by 15%</li>
                    <li>Customer satisfaction scores improved</li>
                    <li>Resource utilization optimized</li>
                </ul>
                
                <h3>Recommendations</h3>
                <ol>
                    <li>Implement process automation</li>
                    <li>Establish performance metrics dashboard</li>
                    <li>Conduct regular efficiency reviews</li>
                </ol>
            </div>
            '''
        }
    ]
    
    for report_data in sample_reports:
        DATA_STORE['audit_reports'][report_data['id']] = report_data
    
    print(f"Initialized sample data: {len(DATA_STORE['users'])} users, {len(DATA_STORE['departments'])} departments, {len(DATA_STORE['audit_reports'])} reports")

def get_data_store():
    """Get the global data store"""
    return DATA_STORE

def find_user_by_email(email):
    """Find user by email address"""
    for user_id, user in DATA_STORE['users'].items():
        if user.get('email') == email:
            return user
    return None

def add_audit_log(user_id, action, entity_type, entity_id=None, details=None, ip_address=None, user_agent=None):
    """Add audit log entry"""
    log_id = str(uuid.uuid4())
    log_data = {
        'id': log_id,
        'user_id': user_id,
        'action': action,
        'entity_type': entity_type,
        'entity_id': entity_id,
        'details': details,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'created_at': datetime.now()
    }
    DATA_STORE['audit_logs'][log_id] = log_data
    return log_id