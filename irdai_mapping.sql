-- IRDAI Evidence Requirements and ISO 27001 Mapping

-- Step 1: Evidence requirements per IRDAI area
INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Anomaly Detection Policy', 'Policy document defining exception handling and anomaly detection procedures', 'document', TRUE, 'quarterly',
  'Collect and maintain Anomaly Detection Policy as evidence for IRDAI DE.AE compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.DE.AE.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Anomaly Detection Policy');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'SIEM Alert Reports', 'Security Information and Event Management alert logs and reports', 'document', TRUE, 'quarterly',
  'Collect and maintain SIEM Alert Reports as evidence for IRDAI DE.AE compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.DE.AE.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='SIEM Alert Reports');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Security Monitoring Logs', 'Evidence of continuous security monitoring including SIEM logs', 'document', TRUE, 'quarterly',
  'Collect and maintain Security Monitoring Logs as evidence for IRDAI DE.CM compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.DE.CM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Security Monitoring Logs');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Penetration Test Reports', 'Results of external and internal penetration testing', 'document', TRUE, 'quarterly',
  'Collect and maintain Penetration Test Reports as evidence for IRDAI DE.CM compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.DE.CM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Penetration Test Reports');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Vulnerability Assessment Reports', 'Periodic vulnerability scanning reports', 'document', TRUE, 'quarterly',
  'Collect and maintain Vulnerability Assessment Reports as evidence for IRDAI DE.CM compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.DE.CM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Vulnerability Assessment Reports');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Security Awareness Training Records', 'Training completion records for security awareness programs', 'document', TRUE, 'semi_annual',
  'Collect and maintain Security Awareness Training Records as evidence for IRDAI DE.CM compliance', 4
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.DE.CM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Security Awareness Training Records');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Firewall Configuration Evidence', 'Host-based and network firewall configuration documentation', 'document', TRUE, 'quarterly',
  'Collect and maintain Firewall Configuration Evidence as evidence for IRDAI DE.CM compliance', 5
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.DE.CM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Firewall Configuration Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Encryption Implementation Evidence', 'Documentation of encryption at rest and in transit', 'document', TRUE, 'quarterly',
  'Collect and maintain Encryption Implementation Evidence as evidence for IRDAI DE.CM compliance', 6
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.DE.CM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Encryption Implementation Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Multi-Factor Authentication Evidence', 'MFA implementation screenshots and configuration', 'document', TRUE, 'quarterly',
  'Collect and maintain Multi-Factor Authentication Evidence as evidence for IRDAI DE.CM compliance', 7
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.DE.CM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Multi-Factor Authentication Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Network Segmentation Diagrams', 'Network architecture showing micro-segmentation', 'document', TRUE, 'semi_annual',
  'Collect and maintain Network Segmentation Diagrams as evidence for IRDAI DE.CM compliance', 8
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.DE.CM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Network Segmentation Diagrams');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Detection Process Documentation', 'Documented detection processes and procedures', 'document', TRUE, 'semi_annual',
  'Collect and maintain Detection Process Documentation as evidence for IRDAI DE.DP compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.DE.DP.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Detection Process Documentation');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Incident Detection Records', 'Records of detected incidents and alerts', 'document', TRUE, 'semi_annual',
  'Collect and maintain Incident Detection Records as evidence for IRDAI DE.DP compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.DE.DP.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Incident Detection Records');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Asset Inventory Register', 'Complete inventory of all IT assets including hardware, software and cloud', 'document', TRUE, 'quarterly',
  'Collect and maintain Asset Inventory Register as evidence for IRDAI ID.AM compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.AM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Asset Inventory Register');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Asset Classification Policy', 'Policy for classifying information assets by criticality', 'document', TRUE, 'semi_annual',
  'Collect and maintain Asset Classification Policy as evidence for IRDAI ID.AM compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.AM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Asset Classification Policy');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Software Bill of Materials (SBOM)', 'Inventory of software components and dependencies', 'document', TRUE, 'semi_annual',
  'Collect and maintain Software Bill of Materials (SBOM) as evidence for IRDAI ID.AM compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.AM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Software Bill of Materials (SBOM)');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Business Context Documentation', 'Documentation of organizational mission and cybersecurity role', 'document', TRUE, 'annual',
  'Collect and maintain Business Context Documentation as evidence for IRDAI ID.BE compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.BE.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Business Context Documentation');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Dependency Mapping', 'Critical infrastructure and dependency documentation', 'document', TRUE, 'semi_annual',
  'Collect and maintain Dependency Mapping as evidence for IRDAI ID.BE compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.BE.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Dependency Mapping');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Cybersecurity Policy', 'Board-approved cybersecurity policy document', 'document', TRUE, 'quarterly',
  'Collect and maintain Cybersecurity Policy as evidence for IRDAI ID.GV compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.GV.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Cybersecurity Policy');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Governance Structure Documentation', 'CISO/security governance structure and reporting lines', 'document', TRUE, 'semi_annual',
  'Collect and maintain Governance Structure Documentation as evidence for IRDAI ID.GV compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.GV.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Governance Structure Documentation');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Security Roles and Responsibilities', 'Documented security roles, responsibilities and accountability', 'document', TRUE, 'semi_annual',
  'Collect and maintain Security Roles and Responsibilities as evidence for IRDAI ID.GV compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.GV.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Security Roles and Responsibilities');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Compliance Register', 'Register of applicable laws, regulations and contractual requirements', 'document', TRUE, 'quarterly',
  'Collect and maintain Compliance Register as evidence for IRDAI ID.GV compliance', 4
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.GV.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Compliance Register');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Risk Assessment Report', 'Periodic cybersecurity risk assessment documentation', 'document', TRUE, 'quarterly',
  'Collect and maintain Risk Assessment Report as evidence for IRDAI ID.RA compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.RA.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Risk Assessment Report');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Threat Intelligence Reports', 'Threat intelligence feeds and analysis reports', 'document', TRUE, 'semi_annual',
  'Collect and maintain Threat Intelligence Reports as evidence for IRDAI ID.RA compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.RA.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Threat Intelligence Reports');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Vulnerability Register', 'Register of identified vulnerabilities and remediation status', 'document', TRUE, 'quarterly',
  'Collect and maintain Vulnerability Register as evidence for IRDAI ID.RA compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.RA.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Vulnerability Register');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Risk Management Framework', 'Documented risk management strategy and framework', 'document', TRUE, 'quarterly',
  'Collect and maintain Risk Management Framework as evidence for IRDAI ID.RM compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.RM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Risk Management Framework');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Risk Treatment Plan', 'Risk treatment decisions and implementation evidence', 'document', TRUE, 'quarterly',
  'Collect and maintain Risk Treatment Plan as evidence for IRDAI ID.RM compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.RM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Risk Treatment Plan');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Vendor Risk Assessment', 'Third-party/supplier cybersecurity risk assessments', 'document', TRUE, 'quarterly',
  'Collect and maintain Vendor Risk Assessment as evidence for IRDAI ID.SC compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.SC.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Vendor Risk Assessment');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Vendor Contracts with Security Clauses', 'Contracts showing cybersecurity requirements for vendors', 'document', TRUE, 'quarterly',
  'Collect and maintain Vendor Contracts with Security Clauses as evidence for IRDAI ID.SC compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.SC.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Vendor Contracts with Security Clauses');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Supply Chain Risk Register', 'Register of supply chain risks and mitigations', 'document', TRUE, 'semi_annual',
  'Collect and maintain Supply Chain Risk Register as evidence for IRDAI ID.SC compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.ID.SC.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Supply Chain Risk Register');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Access Control Policy', 'Documented identity management and access control policy', 'document', TRUE, 'quarterly',
  'Collect and maintain Access Control Policy as evidence for IRDAI PR.AC compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.AC.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Access Control Policy');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'User Access Reviews', 'Periodic access reviews and recertification records', 'document', TRUE, 'quarterly',
  'Collect and maintain User Access Reviews as evidence for IRDAI PR.AC compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.AC.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='User Access Reviews');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Privileged Access Management Evidence', 'PAM tool logs and privileged account reviews', 'document', TRUE, 'quarterly',
  'Collect and maintain Privileged Access Management Evidence as evidence for IRDAI PR.AC compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.AC.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Privileged Access Management Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'MFA Implementation Evidence', 'Multi-factor authentication deployment evidence', 'document', TRUE, 'quarterly',
  'Collect and maintain MFA Implementation Evidence as evidence for IRDAI PR.AC compliance', 4
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.AC.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='MFA Implementation Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Security Awareness Training Records', 'Employee security awareness training completion records', 'document', TRUE, 'quarterly',
  'Collect and maintain Security Awareness Training Records as evidence for IRDAI PR.AT compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.AT.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Security Awareness Training Records');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Security Training Curriculum', 'Training program content and schedule documentation', 'document', TRUE, 'semi_annual',
  'Collect and maintain Security Training Curriculum as evidence for IRDAI PR.AT compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.AT.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Security Training Curriculum');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Phishing Simulation Reports', 'Anti-phishing training and simulation results', 'document', TRUE, 'semi_annual',
  'Collect and maintain Phishing Simulation Reports as evidence for IRDAI PR.AT compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.AT.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Phishing Simulation Reports');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Data Classification Policy', 'Policy for classifying and handling sensitive data', 'document', TRUE, 'quarterly',
  'Collect and maintain Data Classification Policy as evidence for IRDAI PR.DS compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.DS.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Data Classification Policy');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Data Encryption Evidence', 'Evidence of data encryption implementation', 'document', TRUE, 'quarterly',
  'Collect and maintain Data Encryption Evidence as evidence for IRDAI PR.DS compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.DS.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Data Encryption Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Data Loss Prevention Reports', 'DLP tool configuration and incident reports', 'document', TRUE, 'quarterly',
  'Collect and maintain Data Loss Prevention Reports as evidence for IRDAI PR.DS compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.DS.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Data Loss Prevention Reports');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Data Retention Policy', 'Documented data retention and disposal procedures', 'document', TRUE, 'semi_annual',
  'Collect and maintain Data Retention Policy as evidence for IRDAI PR.DS compliance', 4
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.DS.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Data Retention Policy');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Information Security Policies', 'Complete set of information security policies', 'document', TRUE, 'quarterly',
  'Collect and maintain Information Security Policies as evidence for IRDAI PR.IP compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.IP.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Information Security Policies');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Secure SDLC Documentation', 'Secure software development lifecycle procedures', 'document', TRUE, 'quarterly',
  'Collect and maintain Secure SDLC Documentation as evidence for IRDAI PR.IP compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.IP.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Secure SDLC Documentation');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Configuration Management Records', 'Baseline configurations and change records', 'document', TRUE, 'semi_annual',
  'Collect and maintain Configuration Management Records as evidence for IRDAI PR.IP compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.IP.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Configuration Management Records');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Backup and Recovery Evidence', 'Backup completion reports and recovery test results', 'document', TRUE, 'quarterly',
  'Collect and maintain Backup and Recovery Evidence as evidence for IRDAI PR.IP compliance', 4
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.IP.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Backup and Recovery Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Maintenance Policy', 'IT maintenance and patch management policy', 'document', TRUE, 'semi_annual',
  'Collect and maintain Maintenance Policy as evidence for IRDAI PR.MA compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.MA.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Maintenance Policy');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Patch Management Reports', 'Evidence of timely patching and vulnerability remediation', 'document', TRUE, 'quarterly',
  'Collect and maintain Patch Management Reports as evidence for IRDAI PR.MA compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.MA.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Patch Management Reports');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Firewall Rule Documentation', 'Network and host-based firewall configurations', 'document', TRUE, 'quarterly',
  'Collect and maintain Firewall Rule Documentation as evidence for IRDAI PR.PT compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.PT.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Firewall Rule Documentation');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Audit Log Configuration', 'Audit logging configuration and retention evidence', 'document', TRUE, 'quarterly',
  'Collect and maintain Audit Log Configuration as evidence for IRDAI PR.PT compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.PT.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Audit Log Configuration');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Endpoint Protection Evidence', 'Antivirus/EDR deployment and update reports', 'document', TRUE, 'quarterly',
  'Collect and maintain Endpoint Protection Evidence as evidence for IRDAI PR.PT compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.PR.PT.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Endpoint Protection Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Recovery Communication Plan', 'Stakeholder communication plan during recovery', 'document', TRUE, 'semi_annual',
  'Collect and maintain Recovery Communication Plan as evidence for IRDAI RC.CO compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RC.CO.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Recovery Communication Plan');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Crisis Communication Records', 'Evidence of communication during incidents', 'document', TRUE, 'semi_annual',
  'Collect and maintain Crisis Communication Records as evidence for IRDAI RC.CO compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RC.CO.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Crisis Communication Records');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Post-Incident Review Reports', 'Lessons learned from incidents and recovery improvements', 'document', TRUE, 'semi_annual',
  'Collect and maintain Post-Incident Review Reports as evidence for IRDAI RC.IM compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RC.IM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Post-Incident Review Reports');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Recovery Plan Updates', 'Updated recovery plans incorporating lessons learned', 'document', TRUE, 'semi_annual',
  'Collect and maintain Recovery Plan Updates as evidence for IRDAI RC.IM compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RC.IM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Recovery Plan Updates');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Business Continuity Plan', 'Documented BCP/DRP with IRDAI compliance', 'document', TRUE, 'quarterly',
  'Collect and maintain Business Continuity Plan as evidence for IRDAI RC.RP compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RC.RP.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Business Continuity Plan');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'BCP/DR Test Reports', 'Evidence of BCP/DR testing and exercises', 'document', TRUE, 'quarterly',
  'Collect and maintain BCP/DR Test Reports as evidence for IRDAI RC.RP compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RC.RP.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='BCP/DR Test Reports');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'RTO/RPO Documentation', 'Recovery time and point objectives documentation', 'document', TRUE, 'quarterly',
  'Collect and maintain RTO/RPO Documentation as evidence for IRDAI RC.RP compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RC.RP.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='RTO/RPO Documentation');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Incident Analysis Reports', 'Root cause analysis and forensic investigation reports', 'document', TRUE, 'quarterly',
  'Collect and maintain Incident Analysis Reports as evidence for IRDAI RS.AN compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RS.AN.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Incident Analysis Reports');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Threat Intelligence Integration Evidence', 'Evidence of threat intel used in incident response', 'document', TRUE, 'semi_annual',
  'Collect and maintain Threat Intelligence Integration Evidence as evidence for IRDAI RS.AN compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RS.AN.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Threat Intelligence Integration Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Incident Response Communication Records', 'Communication logs during incident response', 'document', TRUE, 'semi_annual',
  'Collect and maintain Incident Response Communication Records as evidence for IRDAI RS.CO compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RS.CO.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Incident Response Communication Records');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'CERT-In Reporting Evidence', 'Evidence of mandatory incident reporting to CERT-In', 'document', TRUE, 'quarterly',
  'Collect and maintain CERT-In Reporting Evidence as evidence for IRDAI RS.CO compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RS.CO.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='CERT-In Reporting Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Regulatory Notification Records', 'Records of notifications to IRDAI during incidents', 'document', TRUE, 'quarterly',
  'Collect and maintain Regulatory Notification Records as evidence for IRDAI RS.CO compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RS.CO.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Regulatory Notification Records');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Incident Response Plan Updates', 'Updated IRP based on lessons learned', 'document', TRUE, 'semi_annual',
  'Collect and maintain Incident Response Plan Updates as evidence for IRDAI RS.IM compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RS.IM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Incident Response Plan Updates');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Response Metrics Reports', 'KPIs for incident response effectiveness', 'document', TRUE, 'annual',
  'Collect and maintain Response Metrics Reports as evidence for IRDAI RS.IM compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RS.IM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Response Metrics Reports');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Containment Evidence', 'Evidence of incident containment actions taken', 'document', TRUE, 'quarterly',
  'Collect and maintain Containment Evidence as evidence for IRDAI RS.MI compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RS.MI.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Containment Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Eradication Records', 'Records of threat eradication and cleanup', 'document', TRUE, 'quarterly',
  'Collect and maintain Eradication Records as evidence for IRDAI RS.MI compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RS.MI.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Eradication Records');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Incident Response Plan', 'Documented incident response procedures', 'document', TRUE, 'quarterly',
  'Collect and maintain Incident Response Plan as evidence for IRDAI RS.RP compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RS.RP.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Incident Response Plan');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'IRP Test/Exercise Records', 'Tabletop exercise and IRP testing records', 'document', TRUE, 'quarterly',
  'Collect and maintain IRP Test/Exercise Records as evidence for IRDAI RS.RP compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RS.RP.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='IRP Test/Exercise Records');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Incident Register', 'Log of all security incidents and response actions', 'document', TRUE, 'quarterly',
  'Collect and maintain Incident Register as evidence for IRDAI RS.RP compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.RS.RP.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Incident Register');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Remote Work Security Policy', 'Security policy for work from remote locations', 'document', TRUE, 'quarterly',
  'Collect and maintain Remote Work Security Policy as evidence for IRDAI WFRL compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.WFRL.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Remote Work Security Policy');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'VPN Implementation Evidence', 'VPN deployment and MFA for remote access evidence', 'document', TRUE, 'quarterly',
  'Collect and maintain VPN Implementation Evidence as evidence for IRDAI WFRL compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.WFRL.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='VPN Implementation Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Remote Access Logs', 'Logs of remote access sessions and monitoring', 'document', TRUE, 'semi_annual',
  'Collect and maintain Remote Access Logs as evidence for IRDAI WFRL compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.WFRL.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Remote Access Logs');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Remote Device Management Evidence', 'MDM/endpoint security for remote devices', 'document', TRUE, 'quarterly',
  'Collect and maintain Remote Device Management Evidence as evidence for IRDAI WFRL compliance', 4
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.WFRL.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Remote Device Management Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Remote Work Security Investment Plan', 'Budget and investment plan for remote work security', 'document', TRUE, 'semi_annual',
  'Collect and maintain Remote Work Security Investment Plan as evidence for IRDAI WFRL.IN compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.WFRL.IN.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Remote Work Security Investment Plan');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Remote Security Tool Procurement Evidence', 'Evidence of security tool investments for remote work', 'document', TRUE, 'semi_annual',
  'Collect and maintain Remote Security Tool Procurement Evidence as evidence for IRDAI WFRL.IN compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.WFRL.IN.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Remote Security Tool Procurement Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'IT Intermediary Policy', 'Compliance policy for IT Intermediary Guidelines 2021', 'document', TRUE, 'quarterly',
  'Collect and maintain IT Intermediary Policy as evidence for IRDAI IGDM compliance', 1
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.IGDM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='IT Intermediary Policy');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'User Agreement/Terms of Service', 'Published terms with prohibited content rules', 'document', TRUE, 'quarterly',
  'Collect and maintain User Agreement/Terms of Service as evidence for IRDAI IGDM compliance', 2
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.IGDM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='User Agreement/Terms of Service');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'Grievance Officer Appointment', 'Published Grievance Officer details and mechanism', 'document', TRUE, 'quarterly',
  'Collect and maintain Grievance Officer Appointment as evidence for IRDAI IGDM compliance', 3
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.IGDM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='Grievance Officer Appointment');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, '72-Hour Reporting Evidence', 'Evidence of timely content takedown within 24 hours', 'document', TRUE, 'quarterly',
  'Collect and maintain 72-Hour Reporting Evidence as evidence for IRDAI IGDM compliance', 4
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.IGDM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='72-Hour Reporting Evidence');

INSERT INTO evidence_requirements (control_id, framework_id, title, description, evidence_type, is_mandatory, frequency, guidance, sort_order)
SELECT c.id, f.id, 'CERT-In Compliance Evidence', 'Evidence of cybersecurity incident reporting to CERT-In within 72 hours', 'document', TRUE, 'quarterly',
  'Collect and maintain CERT-In Compliance Evidence as evidence for IRDAI IGDM compliance', 5
FROM controls c, frameworks f
WHERE c.code = (SELECT code FROM controls WHERE code LIKE 'IRDAI.IGDM.%' ORDER BY code LIMIT 1)
AND f.code = 'IRDAI_CSF'
AND NOT EXISTS (SELECT 1 FROM evidence_requirements er WHERE er.control_id=c.id AND er.title='CERT-In Compliance Evidence');

-- Step 2: Create cross-reference table
CREATE TABLE IF NOT EXISTS control_cross_references (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_control_id UUID REFERENCES controls(id) ON DELETE CASCADE,
  target_control_id UUID REFERENCES controls(id) ON DELETE CASCADE,
  source_framework_code VARCHAR NOT NULL,
  target_framework_code VARCHAR NOT NULL,
  mapping_type VARCHAR DEFAULT 'related',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(source_control_id, target_control_id)
);

-- Step 3: Insert IRDAI → ISO 27001 cross-references
INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.AE.%'
AND cfm.clause_reference='8.16'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.AE.%'
AND cfm.clause_reference='8.15'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.AE.%'
AND cfm.clause_reference='5.25'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.AE.%'
AND cfm.clause_reference='5.26'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.CM.%'
AND cfm.clause_reference='8.16'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.CM.%'
AND cfm.clause_reference='8.15'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.CM.%'
AND cfm.clause_reference='8.8'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.CM.%'
AND cfm.clause_reference='8.7'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.CM.%'
AND cfm.clause_reference='8.20'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.CM.%'
AND cfm.clause_reference='8.22'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.CM.%'
AND cfm.clause_reference='5.9'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.CM.%'
AND cfm.clause_reference='8.3'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.DP.%'
AND cfm.clause_reference='5.24'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.DP.%'
AND cfm.clause_reference='5.25'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.DP.%'
AND cfm.clause_reference='5.26'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.DE.DP.%'
AND cfm.clause_reference='8.16'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.AM.%'
AND cfm.clause_reference='5.9'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.AM.%'
AND cfm.clause_reference='5.10'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.AM.%'
AND cfm.clause_reference='5.11'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.AM.%'
AND cfm.clause_reference='5.12'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.AM.%'
AND cfm.clause_reference='5.13'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.AM.%'
AND cfm.clause_reference='8.10'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.BE.%'
AND cfm.clause_reference='5.1'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.BE.%'
AND cfm.clause_reference='5.2'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.BE.%'
AND cfm.clause_reference='5.4'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.GV.%'
AND cfm.clause_reference='5.1'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.GV.%'
AND cfm.clause_reference='5.2'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.GV.%'
AND cfm.clause_reference='5.3'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.GV.%'
AND cfm.clause_reference='5.4'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.GV.%'
AND cfm.clause_reference='5.31'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.GV.%'
AND cfm.clause_reference='5.36'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.RA.%'
AND cfm.clause_reference='5.7'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.RA.%'
AND cfm.clause_reference='6.1.2'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.RA.%'
AND cfm.clause_reference='8.8'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.RM.%'
AND cfm.clause_reference='5.8'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.RM.%'
AND cfm.clause_reference='6.1.3'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.SC.%'
AND cfm.clause_reference='5.19'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.SC.%'
AND cfm.clause_reference='5.20'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.SC.%'
AND cfm.clause_reference='5.21'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.ID.SC.%'
AND cfm.clause_reference='5.22'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.AC.%'
AND cfm.clause_reference='5.15'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.AC.%'
AND cfm.clause_reference='5.16'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.AC.%'
AND cfm.clause_reference='5.17'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.AC.%'
AND cfm.clause_reference='5.18'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.AC.%'
AND cfm.clause_reference='8.1'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.AC.%'
AND cfm.clause_reference='8.2'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.AC.%'
AND cfm.clause_reference='8.3'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.AC.%'
AND cfm.clause_reference='8.4'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.AC.%'
AND cfm.clause_reference='8.5'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.AT.%'
AND cfm.clause_reference='6.3'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.AT.%'
AND cfm.clause_reference='6.8'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.DS.%'
AND cfm.clause_reference='5.10'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.DS.%'
AND cfm.clause_reference='5.12'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.DS.%'
AND cfm.clause_reference='5.13'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.DS.%'
AND cfm.clause_reference='8.10'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.DS.%'
AND cfm.clause_reference='8.11'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.DS.%'
AND cfm.clause_reference='8.12'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.DS.%'
AND cfm.clause_reference='8.24'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.IP.%'
AND cfm.clause_reference='5.1'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.IP.%'
AND cfm.clause_reference='5.37'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.IP.%'
AND cfm.clause_reference='8.9'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.IP.%'
AND cfm.clause_reference='8.25'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.IP.%'
AND cfm.clause_reference='8.26'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.IP.%'
AND cfm.clause_reference='8.27'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.IP.%'
AND cfm.clause_reference='8.28'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.IP.%'
AND cfm.clause_reference='8.29'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.IP.%'
AND cfm.clause_reference='8.30'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.MA.%'
AND cfm.clause_reference='5.37'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.MA.%'
AND cfm.clause_reference='8.32'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.PT.%'
AND cfm.clause_reference='8.6'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.PT.%'
AND cfm.clause_reference='8.7'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.PT.%'
AND cfm.clause_reference='8.8'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.PT.%'
AND cfm.clause_reference='8.20'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.PT.%'
AND cfm.clause_reference='8.21'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.PT.%'
AND cfm.clause_reference='8.22'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.PR.PT.%'
AND cfm.clause_reference='8.23'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RC.CO.%'
AND cfm.clause_reference='5.26'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RC.CO.%'
AND cfm.clause_reference='5.29'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RC.CO.%'
AND cfm.clause_reference='5.30'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RC.IM.%'
AND cfm.clause_reference='5.27'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RC.IM.%'
AND cfm.clause_reference='10.1'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RC.IM.%'
AND cfm.clause_reference='10.2'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RC.RP.%'
AND cfm.clause_reference='5.29'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RC.RP.%'
AND cfm.clause_reference='5.30'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RC.RP.%'
AND cfm.clause_reference='8.13'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RC.RP.%'
AND cfm.clause_reference='8.14'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RS.AN.%'
AND cfm.clause_reference='5.25'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RS.AN.%'
AND cfm.clause_reference='5.26'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RS.AN.%'
AND cfm.clause_reference='8.16'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RS.CO.%'
AND cfm.clause_reference='5.24'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RS.CO.%'
AND cfm.clause_reference='5.26'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RS.IM.%'
AND cfm.clause_reference='5.27'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RS.IM.%'
AND cfm.clause_reference='10.1'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RS.MI.%'
AND cfm.clause_reference='5.26'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RS.MI.%'
AND cfm.clause_reference='8.8'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RS.RP.%'
AND cfm.clause_reference='5.24'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RS.RP.%'
AND cfm.clause_reference='5.25'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.RS.RP.%'
AND cfm.clause_reference='5.26'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.WFRL.%'
AND cfm.clause_reference='6.7'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.WFRL.%'
AND cfm.clause_reference='8.1'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.WFRL.%'
AND cfm.clause_reference='5.15'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.WFRL.%'
AND cfm.clause_reference='5.16'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.WFRL.IN.%'
AND cfm.clause_reference='6.7'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.WFRL.IN.%'
AND cfm.clause_reference='8.1'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.IGDM.%'
AND cfm.clause_reference='5.31'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.IGDM.%'
AND cfm.clause_reference='5.32'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.IGDM.%'
AND cfm.clause_reference='5.33'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

INSERT INTO control_cross_references (source_control_id, target_control_id, source_framework_code, target_framework_code, mapping_type)
SELECT irdai.id, iso.id, 'IRDAI_CSF', 'ISO_27001', 'equivalent'
FROM controls irdai, controls iso
JOIN control_framework_map cfm ON cfm.control_id=iso.id
JOIN frameworks f ON f.id=cfm.framework_id AND f.code='ISO_27001'
WHERE irdai.code LIKE 'IRDAI.IGDM.%'
AND cfm.clause_reference='5.34'
AND iso.tenant_id IS NULL
ON CONFLICT DO NOTHING;

-- Verify
SELECT COUNT(*) as irdai_evidence FROM evidence_requirements er JOIN frameworks f ON f.id=er.framework_id WHERE f.code='IRDAI_CSF';
SELECT COUNT(*) as cross_refs FROM control_cross_references WHERE source_framework_code='IRDAI_CSF';