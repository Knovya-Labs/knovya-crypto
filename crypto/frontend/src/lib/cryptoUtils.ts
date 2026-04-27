

const PBKDF2_ITERATIONS = 600_000
const MIN_PBKDF2_ITERATIONS = 600_000
const AES_KEY_LENGTH = 256
const IV_LENGTH = 12
const SALT_LENGTH = 16


const ENCRYPTION_VERSION = 3

export interface EncryptionMetadata {
  v: number
  alg: 'AES-256-GCM'
  kdf: 'PBKDF2'
  iter: number
  hash: 'SHA-256'
  salt: string
  iv: string
  wrappedDek: string
  dekIv: string
}

export interface EncryptedPayload {
  ciphertext: string
  metadata: EncryptionMetadata
}


function toBase64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}


export async function deriveKEK(
  password: string,
  salt: Uint8Array,
  iterations = PBKDF2_ITERATIONS,
): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    false,
    ['wrapKey', 'unwrapKey'],
  )
}

export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH))
}


export async function generateDEK(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    true,
    ['encrypt', 'decrypt'],
  )
}


export async function reimportAsNonExtractable(
  extractableDek: CryptoKey,
): Promise<CryptoKey> {
  const raw = await crypto.subtle.exportKey('raw', extractableDek)
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    false,
    ['encrypt', 'decrypt'],
  )
}

export async function wrapDEK(
  kek: CryptoKey,
  dek: CryptoKey,
): Promise<{ wrappedKey: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
  const wrapped = await crypto.subtle.wrapKey('raw', dek, kek, {
    name: 'AES-GCM',
    iv,
  })
  return { wrappedKey: toBase64(wrapped), iv: toBase64(iv) }
}

export async function unwrapDEK(
  kek: CryptoKey,
  wrappedKeyB64: string,
  ivB64: string,
): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    'raw',
    fromBase64(wrappedKeyB64),
    kek,
    { name: 'AES-GCM', iv: fromBase64(ivB64) },
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    false,
    ['encrypt', 'decrypt'],
  )
}


export function buildAAD(
  meta: Pick<EncryptionMetadata, 'v' | 'alg' | 'kdf' | 'iter' | 'hash'>,
): Uint8Array {
  return new TextEncoder().encode(
    `knovya:${meta.v}:${meta.alg}:${meta.kdf}:${meta.iter}:${meta.hash}`,
  )
}


export function buildAADv3(
  meta: Pick<EncryptionMetadata, 'v' | 'alg' | 'kdf' | 'iter' | 'hash'>,
  noteId: string,
  workspaceId: string | number,
  userId: string,
): Uint8Array {
  return new TextEncoder().encode(
    `knovya:v=${meta.v}|alg=${meta.alg}|kdf=${meta.kdf}|iter=${meta.iter}|hash=${meta.hash}` +
    `|note=${noteId}|ws=${workspaceId}|user=${userId}`,
  )
}


export function selectAAD(
  meta: Pick<EncryptionMetadata, 'v' | 'alg' | 'kdf' | 'iter' | 'hash'>,
  noteId: string | null | undefined,
  workspaceId: string | number | null | undefined,
  userId: string | null | undefined,
): Uint8Array | undefined {
  if (meta.v >= 3) {
    if (!noteId || workspaceId === null || workspaceId === undefined || !userId) {
      throw new Error('AAD v3 requires noteId, workspaceId and userId')
    }
    return buildAADv3(meta, noteId, workspaceId, userId)
  }
  if (meta.v >= 2) return buildAAD(meta)
  return undefined
}


export async function encryptContent(
  dek: CryptoKey,
  plaintext: string,
  aad?: Uint8Array,
): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
  const encoded = new TextEncoder().encode(plaintext)
  const params: AesGcmParams = { name: 'AES-GCM', iv }
  if (aad) params.additionalData = aad
  const encrypted = await crypto.subtle.encrypt(params, dek, encoded)
  return { ciphertext: toBase64(encrypted), iv: toBase64(iv) }
}

export async function decryptContent(
  dek: CryptoKey,
  ciphertextB64: string,
  ivB64: string,
  aad?: Uint8Array,
): Promise<string> {
  const params: AesGcmParams = { name: 'AES-GCM', iv: fromBase64(ivB64) }
  if (aad) params.additionalData = aad
  const decrypted = await crypto.subtle.decrypt(params, dek, fromBase64(ciphertextB64))
  return new TextDecoder().decode(decrypted)
}


export async function encryptNote(
  password: string,
  content: string,
  noteId: string,
  workspaceId: string | number,
  userId: string,
): Promise<{ payload: EncryptedPayload; kek: CryptoKey; kekSalt: Uint8Array; dek: CryptoKey }> {
  const salt = generateSalt()
  const kek = await deriveKEK(password, salt)
  const extractableDek = await generateDEK()
  const { wrappedKey, iv: dekIv } = await wrapDEK(kek, extractableDek)

  const metaCore = {
    v: ENCRYPTION_VERSION,
    alg: 'AES-256-GCM' as const,
    kdf: 'PBKDF2' as const,
    iter: PBKDF2_ITERATIONS,
    hash: 'SHA-256' as const,
  }
  const aad = buildAADv3(metaCore, noteId, workspaceId, userId)
  const { ciphertext, iv } = await encryptContent(extractableDek, content, aad)

  const metadata: EncryptionMetadata = {
    ...metaCore,
    salt: toBase64(salt),
    iv,
    wrappedDek: wrappedKey,
    dekIv,
  }


  const dek = await reimportAsNonExtractable(extractableDek)
  return { payload: { ciphertext, metadata }, kek, kekSalt: salt, dek }
}


export async function encryptNoteWithKEK(
  kek: CryptoKey,
  kekSaltB64: string,
  content: string,
  noteId: string,
  workspaceId: string | number,
  userId: string,
): Promise<{ payload: EncryptedPayload; dek: CryptoKey }> {
  const extractableDek = await generateDEK()
  const { wrappedKey, iv: dekIv } = await wrapDEK(kek, extractableDek)

  const metaCore = {
    v: ENCRYPTION_VERSION,
    alg: 'AES-256-GCM' as const,
    kdf: 'PBKDF2' as const,
    iter: PBKDF2_ITERATIONS,
    hash: 'SHA-256' as const,
  }
  const aad = buildAADv3(metaCore, noteId, workspaceId, userId)
  const { ciphertext, iv } = await encryptContent(extractableDek, content, aad)

  const metadata: EncryptionMetadata = {
    ...metaCore,
    salt: kekSaltB64,
    iv,
    wrappedDek: wrappedKey,
    dekIv,
  }

  const dek = await reimportAsNonExtractable(extractableDek)
  return { payload: { ciphertext, metadata }, dek }
}


export async function decryptNoteContent(
  kek: CryptoKey,
  metadata: EncryptionMetadata,
  ciphertextB64: string,
  noteId?: string,
  workspaceId?: string | number,
  userId?: string,
): Promise<{ plaintext: string; dek: CryptoKey }> {
  const dek = await unwrapDEK(kek, metadata.wrappedDek, metadata.dekIv)
  const aad = selectAAD(metadata, noteId, workspaceId, userId)
  const plaintext = await decryptContent(dek, ciphertextB64, metadata.iv, aad)
  return { plaintext, dek }
}


export async function deriveKEKFromMetadata(
  password: string,
  metadata: EncryptionMetadata,
): Promise<CryptoKey> {
  if (metadata.alg !== 'AES-256-GCM') throw new Error('Unsupported algorithm')
  if (metadata.kdf !== 'PBKDF2') throw new Error('Unsupported KDF')
  if (metadata.hash !== 'SHA-256') throw new Error('Unsupported hash')
  const safeIter = Math.max(metadata.iter, MIN_PBKDF2_ITERATIONS)
  return deriveKEK(password, fromBase64(metadata.salt), safeIter)
}


export async function buildEncryptionSetup(
  kek: CryptoKey,
  salt: Uint8Array,
): Promise<{ salt: string; wrappedDek: string; dekIv: string }> {
  const testDek = await generateDEK()
  const { wrappedKey, iv: dekIv } = await wrapDEK(kek, testDek)
  return { salt: toBase64(salt), wrappedDek: wrappedKey, dekIv }
}

export { ENCRYPTION_VERSION, MIN_PBKDF2_ITERATIONS }


export async function changeEncryptionPassword(
  oldKek: CryptoKey,
  newPassword: string,
  notes: Array<{ noteId: string; metadata: EncryptionMetadata }>,
): Promise<{
  newKek: CryptoKey
  newSalt: Uint8Array
  updates: Array<{ noteId: string; metadata: EncryptionMetadata }>
}> {
  const newSalt = generateSalt()
  const newKek = await deriveKEK(newPassword, newSalt)

  const updates: Array<{ noteId: string; metadata: EncryptionMetadata }> = []

  for (const { noteId, metadata } of notes) {
    const dek = await unwrapDEK(oldKek, metadata.wrappedDek, metadata.dekIv)
    const { wrappedKey, iv: dekIv } = await wrapDEK(newKek, dek)

    updates.push({
      noteId,
      metadata: {
        ...metadata,
        salt: toBase64(newSalt),
        wrappedDek: wrappedKey,
        dekIv,
      },
    })
  }

  return { newKek, newSalt, updates }
}
