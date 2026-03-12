'use strict';

const crypto = require('crypto');
const { createSigner, AgentSignError } = require('./signer');

// ── Helpers ─────────────────────────────────────────────────────────

function sha256(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

/** Deterministic JSON — recursive key sort to match Python sort_keys=True */
function canonicalJSON(obj) {
  if (obj === null || obj === undefined) return JSON.stringify(obj);
  if (typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const sorted = Object.keys(obj).sort();
  return '{' + sorted.map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

function hashData(data) {
  return sha256(canonicalJSON(data));
}

function nowISO() {
  return new Date().toISOString();
}

// ── AgentSign SDK ───────────────────────────────────────────────────

class AgentSign {
  /**
   * @param {Object} config
   * @param {string} config.serverUrl      — Required. e.g. 'http://localhost:8888'
   * @param {string} [config.apiKey]       — Developer API key for pay endpoints
   * @param {string} [config.signer]       — 'file' | 'pkcs11' | 'aws-kms' | 'azure-keyvault' (default: 'file')
   * @param {Object} [config.pkcs11]       — PKCS#11 config: { library, slot, pin }
   * @param {Object} [config.aws]          — AWS KMS config: { keyId, region }
   * @param {Object} [config.azure]        — Azure KV config: { vaultUrl, keyName }
   * @param {string} [config.creatorId]    — External identity anchor
   */
  constructor(config) {
    if (!config || !config.serverUrl) {
      throw new AgentSignError('serverUrl is required', 'CONFIG');
    }
    this._serverUrl = config.serverUrl.replace(/\/+$/, '');
    this._apiKey = config.apiKey || null;
    this._signerType = config.signer || 'file';
    this._signerConfig = config;
    this._creatorId = config.creatorId || null;

    this._agentId = null;
    this._agentApiKey = null;
    this._signer = null;
  }

  // ── Internal ────────────────────────────────────────────────────

  _initSigner() {
    if (this._signer || !this._agentId) return;
    this._signer = createSigner(this._signerType, this._agentId, this._signerConfig);
  }

  async _fetch(method, path, body, auth) {
    const url = `${this._serverUrl}${path}`;
    const headers = { 'Content-Type': 'application/json' };
    if (auth && this._apiKey) {
      headers['Authorization'] = `Bearer ${this._apiKey}`;
    }

    const opts = { method, headers };
    if (body !== undefined && body !== null) {
      opts.body = JSON.stringify(body);
    }

    const res = await fetch(url, opts);
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = text; }

    if (!res.ok) {
      const err = new AgentSignError(
        typeof data === 'object' ? (data.error || data.detail || JSON.stringify(data)) : text,
        'API'
      );
      err.statusCode = res.status;
      err.body = data;
      throw err;
    }
    return data;
  }

  // ── Agent Lifecycle ─────────────────────────────────────────────

  /**
   * Register a new agent. Enters pipeline at INTAKE.
   * @param {Object} opts
   * @param {string} opts.name        — Required
   * @param {string} [opts.description]
   * @param {string} [opts.code]
   * @param {string} [opts.framework]
   * @param {string} [opts.category]
   * @param {string} [opts.source]
   * @param {string} [opts.githubUrl]
   * @param {string[]} [opts.permissions]
   * @returns {Promise<Object>} — { agent_id, api_key, pipeline_stage, passport, trust_score }
   */
  async register(opts) {
    if (!opts || !opts.name) throw new AgentSignError('name is required', 'VALIDATION');

    const body = { name: opts.name };
    if (opts.description) body.description = opts.description;
    if (opts.code) body.code = opts.code;
    if (opts.framework) body.framework = opts.framework;
    if (opts.category) body.category = opts.category;
    if (opts.source) body.source = opts.source;
    if (opts.githubUrl) body.github_url = opts.githubUrl;
    if (opts.permissions) body.permissions = opts.permissions;
    if (this._creatorId) body.external_identity_id = this._creatorId;

    const res = await this._fetch('POST', '/api/agents/onboard', body);
    this._agentId = res.agent_id;
    this._agentApiKey = res.api_key;
    this._initSigner();
    return res;
  }

  /**
   * Advance agent one pipeline stage.
   * @param {string} [approvedBy] — Who approved (default: 'sdk')
   * @returns {Promise<Object>} — { agent_id, previous_stage, current_stage, checks, trust_score, passport }
   */
  async advance(approvedBy) {
    this._requireAgent();
    return this._fetch('POST', `/api/agents/${this._agentId}/advance`, {
      approved_by: approvedBy || 'sdk',
    });
  }

  /**
   * Advance through all stages until ACTIVE.
   * @returns {Promise<Object>} — Final advance result
   */
  async advanceToActive() {
    this._requireAgent();
    let res;
    const stages = ['INTAKE', 'VETTING', 'TESTING', 'DEV_APPROVED', 'PROD_APPROVED'];
    for (let i = 0; i < stages.length; i++) {
      res = await this.advance('sdk-auto');
      if (res.current_stage === 'ACTIVE') break;
    }
    return res;
  }

  /**
   * Co-sign agent with CA key.
   * @returns {Promise<Object>}
   */
  async cosign() {
    this._requireAgent();
    return this._fetch('POST', `/api/agents/${this._agentId}/cosign`);
  }

  /**
   * Get agent's passport.
   * @returns {Promise<Object>}
   */
  async getPassport() {
    this._requireAgent();
    return this._fetch('GET', `/api/agents/${this._agentId}/passport`);
  }

  /**
   * Revoke agent. Trust drops to 0.
   * @param {string} [reason]
   * @returns {Promise<Object>}
   */
  async revoke(reason) {
    this._requireAgent();
    return this._fetch('POST', `/api/agents/${this._agentId}/revoke`, { reason });
  }

  /**
   * Get agent details.
   * @returns {Promise<Object>}
   */
  async getAgent() {
    this._requireAgent();
    return this._fetch('GET', `/api/agents/${this._agentId}`);
  }

  // ── Payment (Trust Gate) ────────────────────────────────────────

  /**
   * Register a developer account.
   * @param {Object} opts — { name, email, company }
   * @returns {Promise<Object>}
   */
  async registerDeveloper(opts) {
    return this._fetch('POST', '/api/pay/developers/register', opts);
  }

  /**
   * Create wallet for this agent.
   * @param {Object} [opts] — { developer_id, max_per_tx_pence, max_per_day_pence, max_per_month_pence, whitelisted_merchants }
   * @returns {Promise<Object>}
   */
  async createWallet(opts) {
    this._requireAgent();
    return this._fetch('POST', `/api/pay/agents/${this._agentId}/wallet`, opts || {}, true);
  }

  /**
   * Fund agent's wallet.
   * @param {number} amountPence
   * @returns {Promise<Object>}
   */
  async fundWallet(amountPence) {
    this._requireAgent();
    return this._fetch('POST', `/api/pay/agents/${this._agentId}/fund`, {
      amount_pence: amountPence,
    }, true);
  }

  /**
   * Pay through Trust Gate. Every payment gets identity + policy + audit.
   * @param {string} to          — Merchant / service name
   * @param {number} amountPence — Amount in pence
   * @param {string} [description]
   * @returns {Promise<Object>} — { tx_id, status, amount, to, balance, signature, stripe }
   */
  async pay(to, amountPence, description) {
    this._requireAgent();
    return this._fetch('POST', `/api/pay/agents/${this._agentId}/stripe/pay`, {
      to,
      amount_pence: amountPence,
      description,
    }, true);
  }

  /**
   * Generic Stripe action via Trust Gate.
   * @param {string} action — 'pay' | 'create_payment_link' | 'list_payments' | 'refund' | 'balance' | 'list_customers'
   * @param {Object} [data]
   * @returns {Promise<Object>}
   */
  async stripeAction(action, data) {
    this._requireAgent();
    return this._fetch('POST', `/api/pay/agents/${this._agentId}/stripe/${action}`, data || {}, true);
  }

  /**
   * Freeze agent wallet.
   * @returns {Promise<Object>}
   */
  async freeze() {
    this._requireAgent();
    return this._fetch('POST', `/api/pay/agents/${this._agentId}/wallet/freeze`, null, true);
  }

  /**
   * Unfreeze agent wallet.
   * @returns {Promise<Object>}
   */
  async unfreeze() {
    this._requireAgent();
    return this._fetch('POST', `/api/pay/agents/${this._agentId}/wallet/unfreeze`, null, true);
  }

  // ── MCP Trust Gate ──────────────────────────────────────────────

  /**
   * Verify agent can access an MCP tool.
   * @param {string} mcpId
   * @param {string} tool
   * @returns {Promise<Object>} — { decision: 'ALLOW'|'DENY', ... }
   */
  async verifyMCP(mcpId, tool) {
    this._requireAgent();
    return this._fetch('POST', '/api/mcp/verify', {
      agent_id: this._agentId,
      mcp_id: mcpId,
      tool,
    });
  }

  // ── Local Signing (zero network) ────────────────────────────────

  /**
   * Sign an execution locally. No server call.
   * @param {Object} input   — Execution input data
   * @param {Object} output  — Execution output data
   * @returns {Object} — { executionId, executionHash, signature, method, verified, input, output, signedAt }
   */
  sign(input, output) {
    this._requireAgent();
    this._initSigner();

    const executionId = `exec_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
    const inputHash = hashData(input);
    const outputHash = hashData(output);
    const executionHash = sha256(`${this._agentId}:${inputHash}:${outputHash}:${executionId}`);

    const signature = this._signer.sign(executionHash);
    const isAsync = signature instanceof Promise;
    if (isAsync) {
      throw new AgentSignError(
        'Cloud signers (AWS KMS, Azure KV) require signAsync() instead of sign()',
        'ASYNC_SIGNER'
      );
    }

    const verified = this._signer.verify(executionHash, signature);

    return {
      executionId,
      agentId: this._agentId,
      inputHash,
      outputHash,
      executionHash,
      signature,
      method: this._signer.method,
      verified,
      input,
      output,
      signedAt: nowISO(),
    };
  }

  /**
   * Async version of sign() for cloud HSM signers.
   * @param {Object} input
   * @param {Object} output
   * @returns {Promise<Object>}
   */
  async signAsync(input, output) {
    this._requireAgent();
    this._initSigner();

    const executionId = `exec_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
    const inputHash = hashData(input);
    const outputHash = hashData(output);
    const executionHash = sha256(`${this._agentId}:${inputHash}:${outputHash}:${executionId}`);

    const signature = await this._signer.sign(executionHash);
    const verified = await this._signer.verify(executionHash, signature);

    return {
      executionId,
      agentId: this._agentId,
      inputHash,
      outputHash,
      executionHash,
      signature,
      method: this._signer.method,
      verified,
      input,
      output,
      signedAt: nowISO(),
    };
  }

  /**
   * Verify a signed execution. Local only.
   * @param {Object} execution — Result from sign()
   * @returns {boolean|Promise<boolean>}
   */
  verify(execution) {
    this._initSigner();
    return this._signer.verify(execution.executionHash, execution.signature);
  }

  /**
   * Verify output hasn't been tampered with.
   * @param {Object} output    — The output to check
   * @param {Object} execution — Result from sign()
   * @returns {'PASS'|'TAMPERED'}
   */
  verifyOutput(output, execution) {
    const currentHash = hashData(output);
    return currentHash === execution.outputHash ? 'PASS' : 'TAMPERED';
  }

  // ── Utilities ───────────────────────────────────────────────────

  /** Currently registered agent ID */
  get agentId() { return this._agentId; }

  /** Set agent ID (to resume a previous session) */
  set agentId(id) {
    this._agentId = id;
    this._signer = null;
    if (id) this._initSigner();
  }

  /** Close signer resources (HSM sessions, etc.) */
  close() {
    if (this._signer) {
      this._signer.close();
      this._signer = null;
    }
  }

  _requireAgent() {
    if (!this._agentId) {
      throw new AgentSignError('No agent registered. Call register() first or set agentId.', 'NO_AGENT');
    }
  }
}

module.exports = AgentSign;
module.exports.AgentSign = AgentSign;
module.exports.AgentSignError = AgentSignError;
module.exports.createSigner = require('./signer').createSigner;
