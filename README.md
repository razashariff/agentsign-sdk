<p align="center">
  <h1 align="center">AgentSign</h1>
  <p align="center"><strong>Zero Trust Identity & Signing for AI Agents</strong></p>
  <p align="center">
    <a href="https://www.npmjs.com/package/agentsign"><img src="https://img.shields.io/npm/v/agentsign?color=blue" alt="npm"></a>
    <a href="https://www.npmjs.com/package/agentsign"><img src="https://img.shields.io/npm/dm/agentsign" alt="downloads"></a>
    <a href="https://github.com/razashariff/agentsign-sdk"><img src="https://img.shields.io/github/stars/razashariff/agentsign-sdk?style=social" alt="stars"></a>
    <a href="https://github.com/razashariff/agentsign-sdk/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-BSL%201.1-green" alt="license"></a>
    <a href="https://agentsearch.cybersecai.co.uk/trust"><img src="https://agentsearch.cybersecai.co.uk/badge/agentsign?v=2" alt="AgenticSearch Trust"></a>
  </p>
  <p align="center">
    <a href="https://colab.research.google.com/github/razashariff/agentsign-sdk/blob/main/agentsign_demo.ipynb"><img src="https://colab.research.google.com/assets/colab-badge.svg" alt="Open in Colab"></a>
  </p>
  <p align="center">
    <a href="https://agentsign.dev">Website</a> |
    <a href="https://agentsign.dev/#how-it-works">How It Works</a> |
    <a href="https://github.com/razashariff/agentsign">Self-Host Server</a> |
    <a href="https://www.npmjs.com/package/agentsign">npm</a>
  </p>
</p>

---

Every AI agent gets a **cryptographic passport**. Every execution is **signed**. Every MCP tool call is **verified**. No verification, no trust.

AgentSign is the identity and trust layer for autonomous AI agents. While tools like SSL verify *who* is connecting, AgentSign verifies **who the agent is + what it did + proof it wasn't tampered with + its trust history**.

**Zero runtime dependencies.** Node >= 18. Patent Pending.

## Why AgentSign?

AI agents are now autonomous -- they make API calls, access databases, execute code, and spend money. But there's no standard way to:

- **Verify an agent's identity** before granting tool access
- **Prove what an agent did** with cryptographic evidence
- **Revoke a compromised agent** (or an entire swarm) instantly
- **Score trust** based on actual behavior, not just permissions
- **Verify agent integrity offline** -- no server dependency

AgentSign solves all five. On-prem. Your keys. Your infrastructure.

## Install

```bash
npm install agentsign
```

## Quick Start (5 lines)

```javascript
const AgentSign = require('agentsign');

const agent = new AgentSign({ serverUrl: 'https://agentsign.internal:8888' });

// 1. Register -- agent enters identity pipeline
const { agent_id } = await agent.register({ name: 'Procurement Bot', category: 'finance' });

// 2. Advance through pipeline (INTAKE -> VETTING -> TESTING -> ACTIVE)
await agent.advanceToActive();

// 3. Get self-verifying passport (works offline)
const passport = await agent.getPassport();
// -> { agent_id, name, code_hash, trust_score: 85, pipeline_stage: 'ACTIVE', signature, ... }

// 4. Present passport to MCP server before using tools
const gate = await agent.verifyMCP('database-mcp', 'query_users');
// -> { decision: 'ALLOW', trust_score: 85, checks_passed: ['identity', 'trust', 'pipeline'] }

// 5. Sign every execution (cryptographic proof)
const signed = agent.sign({ query: 'SELECT * FROM users' }, { rows: 142 });
agent.verify(signed); // -> true (tamper-proof)
```

## How It Works

```
                    +------------------+
                    |   AgentSign      |
                    |   Engine (8888)  |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
        +-----v-----+  +----v----+  +------v------+
        | Identity   |  | Trust   |  | Execution   |
        | Pipeline   |  | Scoring |  | Ledger      |
        +-----+------+  +----+----+  +------+------+
              |              |              |
    INTAKE -> VETTING -> TESTING -> ACTIVE  |
              |              |              |
        +-----v-----+  +----v----+  +------v------+
        | Agent      |  | MCP     |  | Swarm       |
        | Passport   |  | Trust   |  | Management  |
        | (offline)  |  | Layer   |  | (revoke all)|
        +------------+  +---------+  +-------------+
```

### The Five Subsystems

| # | Subsystem | What It Does |
|---|-----------|-------------|
| 1 | **Identity Pipeline** | Agents go through INTAKE -> VETTING -> TESTING -> ACTIVE. Each gate is cryptographically recorded. |
| 2 | **Agent Passport** | Self-contained signed JSON. Agent carries it everywhere. Any system can verify offline. |
| 3 | **Execution Chains** | Every input/output pair is signed. Creates a tamper-proof DAG of what the agent did. |
| 4 | **MCP Trust Layer** | MCP servers call `/api/mcp/verify` before granting tool access. Identity + trust + policy check. |
| 5 | **Trust Scoring** | 0-100 score based on code attestation, execution history, success rate, pipeline stage. |

## MCP Trust Layer

The killer feature. Every MCP tool call goes through identity verification:

```javascript
// MCP server middleware (server-side)
app.post('/tools/query', async (req, res) => {
  // Agent presents passport, AgentSign decides ALLOW or DENY
  const gate = await fetch('http://agentsign:8888/api/mcp/verify', {
    method: 'POST',
    body: JSON.stringify({
      agent_id: req.headers['x-agent-id'],
      passport: req.headers['x-agent-passport'],
      mcp_server_id: 'database-mcp',
      tool_name: 'query'
    })
  });
  const { decision } = await gate.json();
  if (decision !== 'ALLOW') return res.status(403).json({ error: 'Trust gate denied' });
  // ... execute tool
});
```

## Local Signing (Zero Network)

Sign and verify locally. No server calls. No network dependency.

```javascript
const signed = agent.sign(
  { invoice: 'INV-001', amount: 350 },           // input
  { status: 'paid', txId: 'tx_abc123' }           // output
);
// -> { executionId, executionHash, signature, method: 'hmac', verified: true }

agent.verify(signed);                              // -> true
agent.verifyOutput({ status: 'paid', txId: 'tx_abc123' }, signed); // -> 'PASS'
```

## HSM & Cloud KMS Support

Default signer is file-based (keyed hashing, keys at `~/.agentsign/keys/`). For hardware security:

| Signer | Install | Use Case |
|--------|---------|----------|
| **File** (default) | -- | Dev, testing, small deployments |
| **PKCS#11** | `npm i pkcs11js` | Thales, SafeNet, YubiHSM, SoftHSM |
| **AWS KMS** | `npm i @aws-sdk/client-kms` | AWS / CloudHSM |
| **Azure Key Vault** | `npm i @azure/keyvault-keys @azure/identity` | Azure |
| **GCP Cloud KMS** | `npm i @google-cloud/kms` | Google Cloud |
| **HashiCorp Vault** | -- (native fetch) | Vault Transit engine |

```javascript
// Example: AWS KMS
const agent = new AgentSign({
  serverUrl: 'http://localhost:8888',
  signer: 'aws-kms',
  aws: { keyId: 'arn:aws:kms:eu-west-2:123:key/abc-def', region: 'eu-west-2' },
});
const signed = await agent.signAsync(input, output);
```

## Self-Host the Engine

```bash
# Docker (recommended)
docker run -d -p 8888:8888 -v agentsign-data:/app/data ghcr.io/razashariff/agentsign:latest

# Or Helm (Kubernetes)
helm install agentsign ./deploy/helm/agentsign \
  --set signer=aws-kms \
  --set aws.keyId=arn:aws:kms:eu-west-2:123:key/abc
```

Server repo: [github.com/razashariff/agentsign](https://github.com/razashariff/agentsign)

## API Reference

| Method | Description |
|--------|-------------|
| `register({ name, category })` | Register agent, enters INTAKE pipeline stage |
| `advance()` | Advance one pipeline stage |
| `advanceToActive()` | Auto-advance to ACTIVE |
| `getPassport()` | Get self-verifying passport (works offline) |
| `getAgent()` | Get agent details + trust score |
| `revoke(reason)` | Instant revocation |
| `verifyMCP(mcpId, tool)` | Present passport to MCP Trust Gate |
| `sign(input, output)` | Local cryptographic signing |
| `verify(execution)` | Verify signed execution |
| `verifyOutput(output, exec)` | Check output integrity |
| `pay(to, pence, desc)` | Trust Gate payment (identity + policy + Stripe) |
| `freeze()` / `unfreeze()` | Freeze/unfreeze agent wallet |

## Pipeline Stages

```
INTAKE --> VETTING --> TESTING --> DEV_APPROVED --> PROD_APPROVED --> ACTIVE
                                                                       |
                                                                   REVOKED
```

## Comparison

| | AgentSign | API Keys | OAuth | mTLS |
|---|---|---|---|---|
| Agent identity | Cryptographic passport | Shared secret | Token (human-centric) | Cert (connection only) |
| What agent did | Signed execution chain | Nothing | Nothing | Nothing |
| Tamper detection | Cryptographic hash chain | None | None | None |
| Trust scoring | 0-100 behavioral | None | Scopes (static) | None |
| Offline verification | Yes (passport) | No | No | Partial |
| Swarm revocation | Instant (all agents) | Manual | Manual | CRL lag |
| MCP integration | Native Trust Gate | None | None | None |

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

BSL 1.1. Patent Pending.

Built by [CyberSecAI](https://cybersecai.com). Website: [agentsign.dev](https://agentsign.dev).
