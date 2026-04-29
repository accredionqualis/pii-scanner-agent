import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'pg';

// System connector definitions
const CONNECTOR_TEMPLATES = {
  freshservice: {
    name: 'Freshservice',
    connection_type: 'rest_api',
    supports_consent_push: false,
    supports_dsr_access: true,
    supports_dsr_erasure: true,
    supports_dsr_portability: true,
    config_fields: ['api_key', 'domain'], // domain = yourcompany.freshservice.com
    base_url: (cfg: any) => `https://${cfg.domain}/api/v2`,
  },
  zendesk: {
    name: 'Zendesk',
    connection_type: 'rest_api',
    supports_consent_push: false,
    supports_dsr_access: true,
    supports_dsr_erasure: true,
    supports_dsr_portability: true,
    config_fields: ['api_token', 'email', 'subdomain'],
    base_url: (cfg: any) => `https://${cfg.subdomain}.zendesk.com/api/v2`,
  },
  gupshup: {
    name: 'Gupshup',
    connection_type: 'rest_api',
    supports_consent_push: true,
    supports_dsr_access: true,
    supports_dsr_erasure: false,
    supports_dsr_portability: true,
    config_fields: ['api_key', 'app_name'],
    base_url: () => 'https://api.gupshup.io/sm/api/v1',
  },
  ozonetel: {
    name: 'Ozonetel',
    connection_type: 'rest_api',
    supports_consent_push: false,
    supports_dsr_access: true,
    supports_dsr_erasure: false,
    supports_dsr_portability: true,
    config_fields: ['api_key', 'username'],
    base_url: () => 'https://api.ozonetel.com/v1',
  },
  rise_sfa: {
    name: 'Rise / SFA',
    connection_type: 'rest_api',
    supports_consent_push: true,
    supports_dsr_access: true,
    supports_dsr_erasure: true,
    supports_dsr_portability: true,
    config_fields: ['api_key', 'base_url'],
    base_url: (cfg: any) => cfg.base_url,
  },
  pcc_loyalty: {
    name: 'PCC Loyalty',
    connection_type: 'rest_api',
    supports_consent_push: true,
    supports_dsr_access: true,
    supports_dsr_erasure: true,
    supports_dsr_portability: true,
    config_fields: ['api_key', 'base_url'],
    base_url: (cfg: any) => cfg.base_url,
  },
  sap_s4hana: {
    name: 'SAP S/4HANA',
    connection_type: 'database',
    supports_consent_push: false,
    supports_dsr_access: true,
    supports_dsr_erasure: false, // Manual erasure only in SAP
    supports_dsr_portability: true,
    config_fields: ['host', 'port', 'client', 'username', 'password', 'system_id'],
    base_url: () => null,
  },
  iconnect_hrms: {
    name: 'Iconnect HRMS',
    connection_type: 'database',
    supports_consent_push: false,
    supports_dsr_access: true,
    supports_dsr_erasure: false,
    supports_dsr_portability: true,
    config_fields: ['host', 'port', 'database', 'username', 'password'],
    base_url: () => null,
  },
};

@Injectable()
export class ConnectorsService {
  constructor(@Inject('DB') private db: Pool) {}

  getConnectorTemplates() {
    return Object.entries(CONNECTOR_TEMPLATES).map(([key, tmpl]) => ({
      system_type: key,
      name: tmpl.name,
      connection_type: tmpl.connection_type,
      supports_consent_push: tmpl.supports_consent_push,
      supports_dsr_access: tmpl.supports_dsr_access,
      supports_dsr_erasure: tmpl.supports_dsr_erasure,
      supports_dsr_portability: tmpl.supports_dsr_portability,
      config_fields: tmpl.config_fields,
    }));
  }

  async getConnectors(tenantId: string) {
    const r = await this.db.query(
      `SELECT id, name, system_type, connection_type, is_active,
              last_tested_at, last_test_status, last_test_message,
              supports_consent_push, supports_dsr_access, supports_dsr_erasure,
              supports_dsr_portability, created_at,
              config - 'password' - 'api_key' - 'api_token' as config_safe
       FROM data_source_connectors WHERE tenant_id=$1 ORDER BY created_at DESC`,
      [tenantId]
    );
    return r.rows;
  }

  async createConnector(tenantId: string, userId: string, dto: any) {
    const tmpl = CONNECTOR_TEMPLATES[dto.system_type as keyof typeof CONNECTOR_TEMPLATES];
    const r = await this.db.query(
      `INSERT INTO data_source_connectors 
        (tenant_id, name, system_type, connection_type, config, is_active,
         supports_consent_push, supports_dsr_access, supports_dsr_erasure,
         supports_dsr_portability, created_by)
       VALUES ($1,$2,$3,$4,$5,TRUE,$6,$7,$8,$9,$10) RETURNING *`,
      [tenantId, dto.name || tmpl?.name || dto.system_type,
       dto.system_type, tmpl?.connection_type || 'rest_api',
       JSON.stringify(dto.config || {}),
       tmpl?.supports_consent_push || false,
       tmpl?.supports_dsr_access || false,
       tmpl?.supports_dsr_erasure || false,
       tmpl?.supports_dsr_portability || false,
       userId]
    );
    return r.rows[0];
  }

  async updateConnector(id: string, tenantId: string, dto: any) {
    const r = await this.db.query(
      `UPDATE data_source_connectors SET
         name=COALESCE($3,name), config=COALESCE($4::jsonb,config),
         is_active=COALESCE($5,is_active), updated_at=NOW()
       WHERE id=$1 AND tenant_id=$2 RETURNING *`,
      [id, tenantId, dto.name, dto.config ? JSON.stringify(dto.config) : null, dto.is_active]
    );
    return r.rows[0];
  }

  async deleteConnector(id: string, tenantId: string) {
    await this.db.query(`DELETE FROM data_source_connectors WHERE id=$1 AND tenant_id=$2`, [id, tenantId]);
    return { deleted: true };
  }

  async testConnector(id: string, tenantId: string) {
    const r = await this.db.query(
      `SELECT * FROM data_source_connectors WHERE id=$1 AND tenant_id=$2`, [id, tenantId]
    );
    const connector = r.rows[0];
    if (!connector) throw new Error('Connector not found');

    let status = 'success';
    let message = 'Connection test passed';
    let testResult: any = {};

    try {
      const config = connector.config;
      if (connector.connection_type === 'rest_api') {
        // Test API connectivity based on system type
        if (connector.system_type === 'freshservice') {
          const res = await fetch(`https://${config.domain}/api/v2/agents/me`, {
            headers: { 'Authorization': `Basic ${Buffer.from(config.api_key + ':X').toString('base64')}` }
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          testResult = { http_status: res.status };
        } else if (connector.system_type === 'zendesk') {
          const res = await fetch(`https://${config.subdomain}.zendesk.com/api/v2/users/me.json`, {
            headers: { 'Authorization': `Basic ${Buffer.from(config.email + '/token:' + config.api_token).toString('base64')}` }
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          testResult = { http_status: res.status };
        } else {
          // Generic test - just validate config fields exist
          const tmpl = CONNECTOR_TEMPLATES[connector.system_type as keyof typeof CONNECTOR_TEMPLATES];
          const missing = (tmpl?.config_fields || []).filter((f: string) => !config[f]);
          if (missing.length > 0) throw new Error(`Missing config: ${missing.join(', ')}`);
          message = 'Configuration validated (live test requires VPN/network access)';
        }
      } else {
        message = 'Database connector configured (live test requires network access to DB host)';
      }
    } catch (e: any) {
      status = 'failed';
      message = e.message || 'Connection failed';
    }

    await this.db.query(
      `UPDATE data_source_connectors SET last_tested_at=NOW(), last_test_status=$3, last_test_message=$4 WHERE id=$1 AND tenant_id=$2`,
      [id, tenantId, status, message]
    );
    return { status, message, result: testResult };
  }

  async executeDSRJob(dsrRequestId: string, connectorId: string, tenantId: string, jobType: string) {
    // Create job record
    const jobR = await this.db.query(
      `INSERT INTO connector_dsr_jobs (tenant_id, dsr_request_id, connector_id, job_type, status, started_at)
       VALUES ($1,$2,$3,$4,'running',NOW()) RETURNING id`,
      [tenantId, dsrRequestId, connectorId, jobType]
    );
    const jobId = jobR.rows[0].id;

    const connR = await this.db.query(
      `SELECT * FROM data_source_connectors WHERE id=$1 AND tenant_id=$2`, [connectorId, tenantId]
    );
    const connector = connR.rows[0];

    const dsrR = await this.db.query(
      `SELECT * FROM dsr_requests WHERE id=$1 AND tenant_id=$2`, [dsrRequestId, tenantId]
    );
    const dsr = dsrR.rows[0];

    let result: any = { status: 'completed', data: null, message: '' };

    try {
      const config = connector.config;

      if (connector.system_type === 'freshservice' && connector.connection_type === 'rest_api') {
        const auth = `Basic ${Buffer.from(config.api_key + ':X').toString('base64')}`;
        const base = `https://${config.domain}/api/v2`;

        if (jobType === 'access' || jobType === 'portability') {
          // Search requester by email
          const res = await fetch(`${base}/requesters?query="primary_email:'${dsr.subject_email}'"`, {
            headers: { 'Authorization': auth, 'Content-Type': 'application/json' }
          });
          const data = await res.json();
          result.data = data;
          result.message = `Found ${data.requesters?.length || 0} records in Freshservice`;
        } else if (jobType === 'erasure') {
          // Find and forget requester
          const searchRes = await fetch(`${base}/requesters?query="primary_email:'${dsr.subject_email}'"`, {
            headers: { 'Authorization': auth }
          });
          const searchData = await searchRes.json();
          if (searchData.requesters?.length > 0) {
            const requesterId = searchData.requesters[0].id;
            const delRes = await fetch(`${base}/requesters/${requesterId}/forget`, {
              method: 'DELETE', headers: { 'Authorization': auth }
            });
            result.message = delRes.ok ? 'Data erased from Freshservice' : `Erasure failed: ${delRes.status}`;
          } else {
            result.message = 'No records found to erase';
          }
        }
      } else if (connector.system_type === 'zendesk' && connector.connection_type === 'rest_api') {
        const auth = `Basic ${Buffer.from(config.email + '/token:' + config.api_token).toString('base64')}`;
        const base = `https://${config.subdomain}.zendesk.com/api/v2`;

        if (jobType === 'access' || jobType === 'portability') {
          const res = await fetch(`${base}/users/search.json?query=${encodeURIComponent(dsr.subject_email)}`, {
            headers: { 'Authorization': auth }
          });
          const data = await res.json();
          result.data = data;
          result.message = `Found ${data.users?.length || 0} records in Zendesk`;
        } else if (jobType === 'erasure') {
          const searchRes = await fetch(`${base}/users/search.json?query=${encodeURIComponent(dsr.subject_email)}`, {
            headers: { 'Authorization': auth }
          });
          const searchData = await searchRes.json();
          if (searchData.users?.length > 0) {
            const userId = searchData.users[0].id;
            const delRes = await fetch(`${base}/users/${userId}`, {
              method: 'DELETE', headers: { 'Authorization': auth }
            });
            result.message = delRes.ok ? 'User deleted from Zendesk' : `Deletion failed: ${delRes.status}`;
          }
        }
      } else {
        // For SAP, HRMS, Gupshup, Ozonetel, Rise, PCC — create manual task
        result.message = `Manual action required: ${jobType} request for ${dsr.subject_email} in ${connector.name}. Please process manually and mark complete.`;
        result.status = 'manual_required';
      }
    } catch (e: any) {
      result.status = 'failed';
      result.message = e.message;
    }

    await this.db.query(
      `UPDATE connector_dsr_jobs SET status=$3, result=$4, error_message=$5, completed_at=NOW() WHERE id=$1 AND tenant_id=$2`,
      [jobId, tenantId, result.status, JSON.stringify(result), result.status === 'failed' ? result.message : null]
    );
    return result;
  }

  async getDSRJobs(dsrRequestId: string, tenantId: string) {
    const r = await this.db.query(
      `SELECT j.*, c.name as connector_name, c.system_type
       FROM connector_dsr_jobs j
       JOIN data_source_connectors c ON c.id=j.connector_id
       WHERE j.dsr_request_id=$1 AND j.tenant_id=$2
       ORDER BY j.created_at DESC`,
      [dsrRequestId, tenantId]
    );
    return r.rows;
  }

  async pushConsent(consentId: string, tenantId: string) {
    const conR = await this.db.query(
      `SELECT * FROM consent_records WHERE id=$1 AND tenant_id=$2`, [consentId, tenantId]
    );
    const consent = conR.rows[0];
    if (!consent) throw new Error('Consent record not found');

    const connR = await this.db.query(
      `SELECT * FROM data_source_connectors WHERE tenant_id=$1 AND supports_consent_push=TRUE AND is_active=TRUE`,
      [tenantId]
    );

    const results = [];
    for (const connector of connR.rows) {
      let status = 'pending';
      let response: any = {};
      try {
        const config = connector.config;
        if (connector.system_type === 'gupshup') {
          // Gupshup consent opt-in/opt-out
          const action = consent.status === 'active' ? 'OPT_IN' : 'OPT_OUT';
          const res = await fetch(`https://api.gupshup.io/sm/api/v1/app/${config.app_name}/optin/user`, {
            method: 'POST',
            headers: { 'apikey': config.api_key, 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `user=${encodeURIComponent(consent.subject_email)}&channel=whatsapp`
          });
          response = { status: res.status };
          status = res.ok ? 'success' : 'failed';
        } else if (connector.system_type === 'rise_sfa' || connector.system_type === 'pcc_loyalty') {
          const res = await fetch(`${config.base_url}/consent`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${config.api_key}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: consent.subject_email, consent_status: consent.status, purpose: consent.purpose })
          });
          response = { status: res.status };
          status = res.ok ? 'success' : 'failed';
        } else {
          status = 'manual_required';
          response = { message: `Manual consent sync needed for ${connector.name}` };
        }
      } catch (e: any) {
        status = 'failed';
        response = { error: e.message };
      }

      await this.db.query(
        `INSERT INTO connector_consent_sync_log (tenant_id, connector_id, consent_record_id, action, status, response)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [tenantId, connector.id, consentId, consent.status === 'active' ? 'push_consent' : 'withdraw_consent', status, JSON.stringify(response)]
      );
      results.push({ connector: connector.name, status, response });
    }
    return results;
  }
}
