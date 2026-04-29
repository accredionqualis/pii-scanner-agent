
-- Data Source Connectors for Consent & DSR
-- Run on both secgrc_db and secgrc_uat_db

CREATE TABLE IF NOT EXISTS data_source_connectors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
  name VARCHAR NOT NULL,
  system_type VARCHAR NOT NULL, -- 'freshservice','zendesk','gupshup','ozonetel','rise_sfa','pcc_loyalty','sap_s4hana','iconnect_hrms','custom'
  connection_type VARCHAR NOT NULL, -- 'rest_api','database','webhook'
  config JSONB NOT NULL DEFAULT '{}', -- encrypted connection details
  is_active BOOLEAN DEFAULT TRUE,
  last_tested_at TIMESTAMPTZ,
  last_test_status VARCHAR, -- 'success','failed','pending'
  last_test_message TEXT,
  -- Capabilities
  supports_consent_push BOOLEAN DEFAULT FALSE,
  supports_dsr_access BOOLEAN DEFAULT FALSE,
  supports_dsr_erasure BOOLEAN DEFAULT FALSE,
  supports_dsr_portability BOOLEAN DEFAULT FALSE,
  -- Metadata
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS connector_dsr_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
  dsr_request_id UUID REFERENCES dsr_requests(id) ON DELETE CASCADE,
  connector_id UUID REFERENCES data_source_connectors(id) ON DELETE CASCADE,
  job_type VARCHAR NOT NULL, -- 'access','erasure','portability','consent_push'
  status VARCHAR DEFAULT 'pending', -- 'pending','running','completed','failed','skipped'
  result JSONB,
  error_message TEXT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS connector_consent_sync_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
  connector_id UUID REFERENCES data_source_connectors(id) ON DELETE CASCADE,
  consent_record_id UUID REFERENCES consent_records(id) ON DELETE CASCADE,
  action VARCHAR NOT NULL, -- 'push_consent','withdraw_consent'
  status VARCHAR DEFAULT 'pending',
  response JSONB,
  synced_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_dsc_tenant ON data_source_connectors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cdj_dsr ON connector_dsr_jobs(dsr_request_id);
CREATE INDEX IF NOT EXISTS idx_cdj_connector ON connector_dsr_jobs(connector_id);
