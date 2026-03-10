'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

class AgentSignError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'AgentSignError';
    this.code = code;
  }
}

// ── FileSigner ──────────────────────────────────────────────────────
// HMAC-SHA256 with auto-generated key stored at ~/.agentsign/keys/{id}.key

class FileSigner {
  constructor(agentId) {
    this.agentId = agentId;
    this.method = 'HMAC-SHA256';
    this._keyDir = path.join(os.homedir(), '.agentsign', 'keys');
    this._keyPath = path.join(this._keyDir, `${agentId}.key`);
    this._key = null;
  }

  _ensureKey() {
    if (this._key) return;
    if (fs.existsSync(this._keyPath)) {
      this._key = fs.readFileSync(this._keyPath);
    } else {
      fs.mkdirSync(this._keyDir, { recursive: true, mode: 0o700 });
      this._key = crypto.randomBytes(32);
      fs.writeFileSync(this._keyPath, this._key, { mode: 0o600 });
    }
  }

  sign(hash) {
    this._ensureKey();
    return crypto.createHmac('sha256', this._key).update(hash).digest('hex');
  }

  verify(hash, signature) {
    this._ensureKey();
    const expected = this.sign(hash);
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(signature, 'hex'));
  }

  close() {
    this._key = null;
  }
}

// ── PKCS11Signer ────────────────────────────────────────────────────
// Hardware HSM via PKCS#11 (Thales, SafeNet, YubiHSM, SoftHSM)

class PKCS11Signer {
  constructor(agentId, config) {
    this.agentId = agentId;
    this.method = 'PKCS11-ECDSA-P256';
    this._config = config || {};
    this._session = null;
    this._pkcs11 = null;
    this._privateKey = null;
    this._publicKey = null;
  }

  _load() {
    if (this._session) return;
    let PKCS11;
    try {
      PKCS11 = require('pkcs11js');
    } catch {
      throw new AgentSignError(
        "PKCS#11 signer requires 'pkcs11js'. Install: npm install pkcs11js",
        'MISSING_DEP'
      );
    }

    const lib = this._config.library;
    if (!lib) throw new AgentSignError('pkcs11.library path is required', 'CONFIG');

    this._pkcs11 = new PKCS11();
    this._pkcs11.load(lib);
    this._pkcs11.C_Initialize();

    const slots = this._pkcs11.C_GetSlotList(true);
    const slot = slots[this._config.slot || 0];
    if (slot === undefined) throw new AgentSignError('No PKCS#11 slot found', 'HSM');

    this._session = this._pkcs11.C_OpenSession(slot, 4 /* CKF_SERIAL_SESSION */ | 2 /* CKF_RW_SESSION */);
    if (this._config.pin) {
      this._pkcs11.C_Login(this._session, 1 /* CKU_USER */, this._config.pin);
    }

    // Find or generate ECDSA P-256 key pair labeled with agentId
    const label = `agentsign-${this.agentId}`;
    this._privateKey = this._findKey(3 /* CKO_PRIVATE_KEY */, label);
    this._publicKey = this._findKey(2 /* CKO_PUBLIC_KEY */, label);

    if (!this._privateKey) {
      // Generate key pair
      const keys = this._pkcs11.C_GenerateKeyPair(
        this._session,
        { mechanism: 0x00001041 /* CKM_EC_KEY_PAIR_GEN */ },
        [
          { type: 0x00000003 /* CKA_LABEL */, value: label },
          { type: 0x00000162 /* CKA_EC_PARAMS */, value: Buffer.from('06082a8648ce3d030107', 'hex') }, // P-256 OID
          { type: 0x00000108 /* CKA_VERIFY */, value: true },
          { type: 0x00000001 /* CKA_TOKEN */, value: true },
        ],
        [
          { type: 0x00000003 /* CKA_LABEL */, value: label },
          { type: 0x00000107 /* CKA_SIGN */, value: true },
          { type: 0x00000001 /* CKA_TOKEN */, value: true },
          { type: 0x00000104 /* CKA_SENSITIVE */, value: true },
        ]
      );
      this._publicKey = keys.publicKey;
      this._privateKey = keys.privateKey;
    }
  }

  _findKey(objClass, label) {
    this._pkcs11.C_FindObjectsInit(this._session, [
      { type: 0x00000000 /* CKA_CLASS */, value: objClass },
      { type: 0x00000003 /* CKA_LABEL */, value: label },
    ]);
    const objs = this._pkcs11.C_FindObjects(this._session, 1);
    this._pkcs11.C_FindObjectsFinal(this._session);
    return objs.length ? objs[0] : null;
  }

  sign(hash) {
    this._load();
    const buf = Buffer.from(hash, 'hex');
    this._pkcs11.C_SignInit(this._session, { mechanism: 0x00001044 /* CKM_ECDSA_SHA256 */ }, this._privateKey);
    const sig = this._pkcs11.C_Sign(this._session, buf, Buffer.alloc(64));
    // Convert raw r||s (32+32 bytes) to hex
    return sig.toString('hex');
  }

  verify(hash, signature) {
    this._load();
    const buf = Buffer.from(hash, 'hex');
    const sig = Buffer.from(signature, 'hex');
    this._pkcs11.C_VerifyInit(this._session, { mechanism: 0x00001044 /* CKM_ECDSA_SHA256 */ }, this._publicKey);
    try {
      this._pkcs11.C_Verify(this._session, buf, sig);
      return true;
    } catch {
      return false;
    }
  }

  close() {
    if (this._session && this._pkcs11) {
      try { this._pkcs11.C_Logout(this._session); } catch {}
      try { this._pkcs11.C_CloseSession(this._session); } catch {}
      try { this._pkcs11.C_Finalize(); } catch {}
    }
    this._session = null;
  }
}

// ── AWSKMSSigner ────────────────────────────────────────────────────
// AWS KMS / CloudHSM — signs with customer-managed ECDSA key

class AWSKMSSigner {
  constructor(agentId, config) {
    this.agentId = agentId;
    this.method = 'AWS-KMS-ECDSA-P256';
    this._config = config || {};
    this._client = null;
  }

  async _load() {
    if (this._client) return;
    let KMSClient, SignCommand, VerifyCommand;
    try {
      ({ KMSClient, SignCommand, VerifyCommand } = require('@aws-sdk/client-kms'));
    } catch {
      throw new AgentSignError(
        "AWS KMS signer requires '@aws-sdk/client-kms'. Install: npm install @aws-sdk/client-kms",
        'MISSING_DEP'
      );
    }
    this._KMSClient = KMSClient;
    this._SignCommand = SignCommand;
    this._VerifyCommand = VerifyCommand;
    this._client = new KMSClient({ region: this._config.region || 'eu-west-2' });
    this._keyId = this._config.keyId;
    if (!this._keyId) throw new AgentSignError('aws.keyId is required', 'CONFIG');
  }

  async sign(hash) {
    await this._load();
    const cmd = new this._SignCommand({
      KeyId: this._keyId,
      Message: Buffer.from(hash, 'hex'),
      MessageType: 'DIGEST',
      SigningAlgorithm: 'ECDSA_SHA_256',
    });
    const res = await this._client.send(cmd);
    return Buffer.from(res.Signature).toString('hex');
  }

  async verify(hash, signature) {
    await this._load();
    const cmd = new this._VerifyCommand({
      KeyId: this._keyId,
      Message: Buffer.from(hash, 'hex'),
      MessageType: 'DIGEST',
      Signature: Buffer.from(signature, 'hex'),
      SigningAlgorithm: 'ECDSA_SHA_256',
    });
    try {
      const res = await this._client.send(cmd);
      return res.SignatureValid;
    } catch {
      return false;
    }
  }

  close() {
    this._client = null;
  }
}

// ── AzureKVSigner ───────────────────────────────────────────────────
// Azure Key Vault — signs with customer-managed key

class AzureKVSigner {
  constructor(agentId, config) {
    this.agentId = agentId;
    this.method = 'AZURE-KV-ECDSA-P256';
    this._config = config || {};
    this._client = null;
  }

  async _load() {
    if (this._client) return;
    let CryptographyClient, DefaultAzureCredential;
    try {
      ({ CryptographyClient } = require('@azure/keyvault-keys'));
      ({ DefaultAzureCredential } = require('@azure/identity'));
    } catch {
      throw new AgentSignError(
        "Azure KV signer requires '@azure/keyvault-keys' and '@azure/identity'. Install: npm install @azure/keyvault-keys @azure/identity",
        'MISSING_DEP'
      );
    }

    const vaultUrl = this._config.vaultUrl;
    const keyName = this._config.keyName;
    if (!vaultUrl || !keyName) throw new AgentSignError('azure.vaultUrl and azure.keyName required', 'CONFIG');

    const credential = new DefaultAzureCredential();
    const { KeyClient } = require('@azure/keyvault-keys');
    const keyClient = new KeyClient(vaultUrl, credential);
    const key = await keyClient.getKey(keyName);
    this._client = new CryptographyClient(key.id, credential);
  }

  async sign(hash) {
    await this._load();
    const res = await this._client.sign('ES256', Buffer.from(hash, 'hex'));
    return Buffer.from(res.result).toString('hex');
  }

  async verify(hash, signature) {
    await this._load();
    try {
      const res = await this._client.verify('ES256', Buffer.from(hash, 'hex'), Buffer.from(signature, 'hex'));
      return res.result;
    } catch {
      return false;
    }
  }

  close() {
    this._client = null;
  }
}

// ── GCPKMSSigner ────────────────────────────────────────────────────
// GCP Cloud KMS — signs with customer-managed ECDSA key

class GCPKMSSigner {
  constructor(agentId, config) {
    this.agentId = agentId;
    this.method = 'GCP-KMS-ECDSA-P256';
    this._config = config || {};
    this._client = null;
  }

  async _load() {
    if (this._client) return;
    let KeyManagementServiceClient;
    try {
      ({ KeyManagementServiceClient } = require('@google-cloud/kms'));
    } catch {
      throw new AgentSignError(
        "GCP KMS signer requires '@google-cloud/kms'. Install: npm install @google-cloud/kms",
        'MISSING_DEP'
      );
    }
    this._client = new KeyManagementServiceClient();
    this._keyName = this._config.keyName;
    if (!this._keyName) throw new AgentSignError('gcp.keyName is required', 'CONFIG');
  }

  async sign(hash) {
    await this._load();
    const digest = { sha256: Buffer.from(hash, 'hex') };
    const [result] = await this._client.asymmetricSign({ name: this._keyName, digest });
    return Buffer.from(result.signature).toString('hex');
  }

  async verify(hash, signature) {
    await this._load();
    // GCP KMS verify requires the public key -- fetch and verify locally
    try {
      const [pubKeyResp] = await this._client.getPublicKey({ name: this._keyName });
      const pubKey = crypto.createPublicKey(pubKeyResp.pem);
      const verify = crypto.createVerify('SHA256');
      verify.update(Buffer.from(hash, 'hex'));
      return verify.verify(pubKey, Buffer.from(signature, 'hex'));
    } catch {
      return false;
    }
  }

  close() {
    this._client = null;
  }
}

// ── VaultSigner ─────────────────────────────────────────────────────
// HashiCorp Vault Transit secrets engine

class VaultSigner {
  constructor(agentId, config) {
    this.agentId = agentId;
    this.method = 'VAULT-TRANSIT';
    this._config = config || {};
    this._addr = this._config.addr;
    this._token = this._config.token;
    this._keyName = this._config.keyName || 'agentsign';
    this._mount = this._config.mount || 'transit';
    if (!this._addr || !this._token) {
      throw new AgentSignError('vault.addr and vault.token are required', 'CONFIG');
    }
  }

  async sign(hash) {
    const digest = crypto.createHash('sha256').update(Buffer.from(hash, 'hex')).digest('base64');
    const url = `${this._addr}/v1/${this._mount}/sign/${this._keyName}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'X-Vault-Token': this._token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: digest, hash_algorithm: 'sha2-256' }),
    });
    if (!res.ok) throw new AgentSignError(`Vault sign failed: ${res.status}`, 'VAULT');
    const data = await res.json();
    // Vault returns "vault:v1:base64signature"
    const sigB64 = data.data.signature.split(':').pop();
    return Buffer.from(sigB64, 'base64').toString('hex');
  }

  async verify(hash, signature) {
    const digest = crypto.createHash('sha256').update(Buffer.from(hash, 'hex')).digest('base64');
    const sigB64 = Buffer.from(signature, 'hex').toString('base64');
    const vaultSig = `vault:v1:${sigB64}`;
    const url = `${this._addr}/v1/${this._mount}/verify/${this._keyName}`;
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'X-Vault-Token': this._token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: digest, signature: vaultSig, hash_algorithm: 'sha2-256' }),
      });
      if (!res.ok) return false;
      const data = await res.json();
      return data.data.valid;
    } catch {
      return false;
    }
  }

  close() {}
}

// ── Factory ─────────────────────────────────────────────────────────

function createSigner(type, agentId, config) {
  switch (type) {
    case 'file':
      return new FileSigner(agentId);
    case 'pkcs11':
      return new PKCS11Signer(agentId, config.pkcs11);
    case 'aws-kms':
      return new AWSKMSSigner(agentId, config.aws);
    case 'azure-keyvault':
      return new AzureKVSigner(agentId, config.azure);
    case 'gcp-kms':
      return new GCPKMSSigner(agentId, config.gcp);
    case 'vault':
      return new VaultSigner(agentId, config.vault);
    default:
      throw new AgentSignError(`Unknown signer type: '${type}'. Use: file | pkcs11 | aws-kms | azure-keyvault | gcp-kms | vault`, 'CONFIG');
  }
}

module.exports = { createSigner, FileSigner, PKCS11Signer, AWSKMSSigner, AzureKVSigner, GCPKMSSigner, VaultSigner, AgentSignError };
