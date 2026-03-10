export class AgentSignError extends Error {
  code: string;
  constructor(message: string, code: string);
}

export interface Signer {
  agentId: string;
  method: string;
  sign(hash: string): string | Promise<string>;
  verify(hash: string, signature: string): boolean | Promise<boolean>;
  close(): void;
}

export interface PKCS11Config {
  library: string;
  slot?: number;
  pin?: string;
}

export interface AWSConfig {
  keyId: string;
  region?: string;
}

export interface AzureConfig {
  vaultUrl: string;
  keyName: string;
}

export interface GCPConfig {
  keyName: string;
}

export interface VaultConfig {
  addr: string;
  token: string;
  keyName?: string;
  mount?: string;
}

export class FileSigner implements Signer {
  agentId: string;
  method: 'HMAC-SHA256';
  constructor(agentId: string);
  sign(hash: string): string;
  verify(hash: string, signature: string): boolean;
  close(): void;
}

export class PKCS11Signer implements Signer {
  agentId: string;
  method: 'PKCS11-ECDSA-P256';
  constructor(agentId: string, config: PKCS11Config);
  sign(hash: string): string;
  verify(hash: string, signature: string): boolean;
  close(): void;
}

export class AWSKMSSigner implements Signer {
  agentId: string;
  method: 'AWS-KMS-ECDSA-P256';
  constructor(agentId: string, config: AWSConfig);
  sign(hash: string): Promise<string>;
  verify(hash: string, signature: string): Promise<boolean>;
  close(): void;
}

export class AzureKVSigner implements Signer {
  agentId: string;
  method: 'AZURE-KV-ECDSA-P256';
  constructor(agentId: string, config: AzureConfig);
  sign(hash: string): Promise<string>;
  verify(hash: string, signature: string): Promise<boolean>;
  close(): void;
}

export class GCPKMSSigner implements Signer {
  agentId: string;
  method: 'GCP-KMS-ECDSA-P256';
  constructor(agentId: string, config: GCPConfig);
  sign(hash: string): Promise<string>;
  verify(hash: string, signature: string): Promise<boolean>;
  close(): void;
}

export class VaultSigner implements Signer {
  agentId: string;
  method: 'VAULT-TRANSIT';
  constructor(agentId: string, config: VaultConfig);
  sign(hash: string): Promise<string>;
  verify(hash: string, signature: string): Promise<boolean>;
  close(): void;
}

export function createSigner(
  type: 'file' | 'pkcs11' | 'aws-kms' | 'azure-keyvault' | 'gcp-kms' | 'vault',
  agentId: string,
  config?: Record<string, any>
): Signer;
