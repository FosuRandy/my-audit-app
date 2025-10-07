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
    """Initialize the system with only the head of business control user"""
    
    # Create only head of business control user
    head_id = str(uuid.uuid4())
    head_data = {
        'id': head_id,
        'email': 'head@audit.system',
        'role': 'head_of_business_control',
        'first_name': 'Business',
        'last_name': 'Control',
        'username': 'head_control',
        'phone': '+1-555-0000',
        'is_active': True,
        'password_reset_required': False,
        'firebase_uid': 'test-head-uid',  # For development authentication
        'created_at': datetime.utcnow(),
        'last_login': None
    }
    DATA_STORE['users'][head_id] = head_data
    
    print(f"Initialized head of business control user: {head_data['email']}")

def get_data_store():
    """Get the global data store"""
    return DATA_STORE

def find_user_by_email(email):
    """Find user by email address - checks both DATA_STORE and Firestore"""
    # First check DATA_STORE (for test users and backwards compatibility)
    for user_id, user in DATA_STORE['users'].items():
        if user.get('email') == email:
            return user
    
    # If not found in DATA_STORE and Firebase is available, check Firestore
    try:
        from firebase_config import FIREBASE_AVAILABLE
        if FIREBASE_AVAILABLE:
            from firebase_models import UserModel
            user_model = UserModel()
            user = user_model.get_user_by_email(email)
            if user:
                return user
    except Exception as e:
        print(f"Error checking Firestore for user: {e}")
    
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