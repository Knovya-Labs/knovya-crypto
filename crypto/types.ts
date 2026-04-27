export enum ENCRYPTION_VERSION {
  V1_UNBOUND = 1,

  V2_AAD_BOUND = 2,

  V3_HKDF_PER_NOTE = 3,
}

export const MIN_PBKDF2_ITERATIONS = 600_000;

export const DEFAULT_PBKDF2_ITERATIONS = 600_000;

export const AES_GCM_IV_LENGTH = 12;

export const AES_GCM_TAG_LENGTH = 16;

export const AES_KEY_LENGTH_BITS = 256;

export const HKDF_DEK_LABEL_V3 = "knovya-dek-v3";

export interface AADComponents {
  readonly note_id: string;
  readonly counter: number;
  readonly version: ENCRYPTION_VERSION;
}

export function buildAAD(components: AADComponents): string {
  return `${components.note_id}|${components.counter}|${components.version}`;
}

export interface EncryptedEnvelope {
  readonly ciphertext: Uint8Array;
  readonly iv: Uint8Array;
  readonly counter: number;
  readonly version: ENCRYPTION_VERSION;
}

export interface EncryptionMetadata {
  readonly version: ENCRYPTION_VERSION;
  readonly iv: string;
  readonly counter: number;
  readonly iter?: number;
  readonly salt?: string;
  readonly algorithm: "AES-256-GCM";
  readonly kdf: "PBKDF2-HMAC-SHA256";
}

export interface KEKEnvelope {
  readonly wrapped_key: Uint8Array;
  readonly wrap_iv: Uint8Array;
  readonly kdf_params: {
    readonly iter: number;
    readonly salt: Uint8Array;
  };
  readonly version: ENCRYPTION_VERSION;
}

export interface RecoveryKey {
  readonly mnemonic: readonly string[];
  readonly checksum: string;
  readonly created_at: string;
}
