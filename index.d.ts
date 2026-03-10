import { Signer, PKCS11Config, AWSConfig, AzureConfig, GCPConfig, VaultConfig, AgentSignError } from './signer';

export { AgentSignError, Signer, PKCS11Config, AWSConfig, AzureConfig, GCPConfig, VaultConfig } from './signer';
export { createSigner } from './signer';

export interface AgentSignConfig {
  /** Server URL (required). e.g. 'http://localhost:8888' */
  serverUrl: string;
  /** Developer API key for pay endpoints */
  apiKey?: string;
  /** Signer type. Default: 'file' */
  signer?: 'file' | 'pkcs11' | 'aws-kms' | 'azure-keyvault' | 'gcp-kms' | 'vault';
  /** PKCS#11 HSM config */
  pkcs11?: PKCS11Config;
  /** AWS KMS config */
  aws?: AWSConfig;
  /** Azure Key Vault config */
  azure?: AzureConfig;
  /** GCP Cloud KMS config */
  gcp?: GCPConfig;
  /** HashiCorp Vault Transit config */
  vault?: VaultConfig;
  /** ProofX creator_id for identity link */
  creatorId?: string;
}

export interface RegisterOpts {
  name: string;
  description?: string;
  code?: string;
  framework?: string;
  category?: string;
  source?: string;
  githubUrl?: string;
  permissions?: string[];
}

export interface RegisterResult {
  agent_id: string;
  api_key: string;
  pipeline_stage: string;
  passport: Record<string, any>;
  trust_score: Record<string, any>;
  message?: string;
}

export interface AdvanceResult {
  agent_id: string;
  previous_stage: string;
  current_stage: string;
  checks: Record<string, boolean>;
  trust_score: Record<string, any>;
  passport: Record<string, any>;
}

export interface SignedExecution {
  executionId: string;
  agentId: string;
  inputHash: string;
  outputHash: string;
  executionHash: string;
  signature: string;
  method: string;
  verified: boolean;
  input: any;
  output: any;
  signedAt: string;
}

export interface PayResult {
  tx_id: string;
  status: string;
  amount: string;
  to: string;
  balance: string;
  signature: Record<string, any>;
  tx_hash: string;
  stripe?: {
    balance_tx_id: string;
    status: string;
    customer_id: string;
    dashboard_url: string;
  };
}

export interface WalletOpts {
  developer_id?: string;
  max_per_tx_pence?: number;
  max_per_day_pence?: number;
  max_per_month_pence?: number;
  requires_approval_above_pence?: number;
  whitelisted_merchants?: string[];
}

export class AgentSign {
  constructor(config: AgentSignConfig);

  get agentId(): string | null;
  set agentId(id: string);

  // Agent lifecycle
  register(opts: RegisterOpts): Promise<RegisterResult>;
  advance(approvedBy?: string): Promise<AdvanceResult>;
  advanceToActive(): Promise<AdvanceResult>;
  cosign(): Promise<Record<string, any>>;
  getPassport(): Promise<Record<string, any>>;
  getAgent(): Promise<Record<string, any>>;
  revoke(reason?: string): Promise<Record<string, any>>;

  // Payment (Trust Gate)
  registerDeveloper(opts: { name: string; email?: string; company?: string }): Promise<Record<string, any>>;
  createWallet(opts?: WalletOpts): Promise<Record<string, any>>;
  fundWallet(amountPence: number): Promise<Record<string, any>>;
  pay(to: string, amountPence: number, description?: string): Promise<PayResult>;
  stripeAction(action: string, data?: Record<string, any>): Promise<Record<string, any>>;
  freeze(): Promise<Record<string, any>>;
  unfreeze(): Promise<Record<string, any>>;

  // MCP Trust Gate
  verifyMCP(mcpId: string, tool: string): Promise<Record<string, any>>;

  // Local signing (zero network)
  sign(input: any, output: any): SignedExecution;
  signAsync(input: any, output: any): Promise<SignedExecution>;
  verify(execution: SignedExecution): boolean | Promise<boolean>;
  verifyOutput(output: any, execution: SignedExecution): 'PASS' | 'TAMPERED';

  close(): void;
}

export default AgentSign;
