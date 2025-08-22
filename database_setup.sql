-- Create tables for audit management system
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    username VARCHAR(100) UNIQUE,
    phone VARCHAR(20),
    is_active BOOLEAN DEFAULT TRUE,
    password_reset_required BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Departments table
CREATE TABLE IF NOT EXISTS departments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audits table
CREATE TABLE IF NOT EXISTS audits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    audit_type VARCHAR(50),
    department_id UUID REFERENCES departments(id),
    status VARCHAR(50) DEFAULT 'draft',
    priority VARCHAR(20) DEFAULT 'medium',
    reference_number VARCHAR(100) UNIQUE,
    auditor_id UUID REFERENCES users(id),
    auditee_id UUID REFERENCES users(id),
    created_by_id UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    planned_start_date DATE,
    planned_end_date DATE,
    director_approved_at TIMESTAMP,
    auditor_assigned_at TIMESTAMP
);

-- Risk assessments table
CREATE TABLE IF NOT EXISTS risk_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    risk_description TEXT NOT NULL,
    department_id UUID REFERENCES departments(id),
    impact_level VARCHAR(20),
    likelihood_level VARCHAR(20),
    risk_score INTEGER,
    risk_level VARCHAR(20),
    mitigation_measures TEXT,
    risk_owner VARCHAR(255),
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID REFERENCES audits(id),
    finding_description TEXT NOT NULL,
    severity VARCHAR(20),
    status VARCHAR(20) DEFAULT 'open',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Corrective actions table
CREATE TABLE IF NOT EXISTS corrective_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID REFERENCES findings(id),
    action_description TEXT NOT NULL,
    responsible_person_id UUID REFERENCES users(id),
    target_date DATE,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID REFERENCES audits(id),
    sender_id UUID REFERENCES users(id),
    recipient_id UUID REFERENCES users(id),
    message_content TEXT NOT NULL,
    message_type VARCHAR(50),
    subject VARCHAR(255),
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Evidence files table
CREATE TABLE IF NOT EXISTS evidence_files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID REFERENCES audits(id),
    filename VARCHAR(255),
    file_path VARCHAR(500),
    file_size INTEGER,
    file_type VARCHAR(100),
    description TEXT,
    uploaded_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit reports table
CREATE TABLE IF NOT EXISTS audit_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID REFERENCES audits(id),
    report_type VARCHAR(50),
    generated_by UUID REFERENCES users(id),
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100),
    entity_type VARCHAR(50),
    entity_id UUID,
    details TEXT,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO users (id, email, role, first_name, last_name, username, phone, is_active, password_reset_required) VALUES
    (uuid_generate_v4(), 'admin@audit.system', 'director', 'System', 'Administrator', 'admin', '+1-555-0001', TRUE, FALSE),
    (uuid_generate_v4(), 'head@audit.system', 'head_of_business_control', 'Business', 'Control', 'head_control', '+1-555-0002', TRUE, FALSE),
    (uuid_generate_v4(), 'auditor@audit.system', 'auditor', 'John', 'Auditor', 'auditor1', '+1-555-0003', TRUE, FALSE),
    (uuid_generate_v4(), 'auditee@audit.system', 'auditee', 'Jane', 'Manager', 'auditee1', '+1-555-0004', TRUE, FALSE)
ON CONFLICT (email) DO NOTHING;

INSERT INTO departments (id, name, description) VALUES
    (uuid_generate_v4(), 'Internal Audit', 'Internal audit department'),
    (uuid_generate_v4(), 'Finance', 'Finance and accounting department'),
    (uuid_generate_v4(), 'Operations', 'Operations department'),
    (uuid_generate_v4(), 'IT', 'Information technology department')
ON CONFLICT DO NOTHING;