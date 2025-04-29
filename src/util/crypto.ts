import { Buffer } from 'node:buffer'
import crypto from 'node:crypto'

/**
 * Generate an AES-256 key from a password and salt using PBKDF2.
 * @param password The password which to derive the key from.
 * @param salt The salt to use in the key derivation.
 * @returns Generated AES-256 key.
 */
export function generateAesKey(password: Buffer, salt: Buffer): Buffer {
  const hash = crypto.createHash('sha256')
  hash.update(password)
  hash.update(salt)
  const saltBuffer = hash.digest()
  // PBKDF2: 100,000 iterations, 32 bytes, SHA-512
  return crypto.pbkdf2Sync(password, saltBuffer, 100000, 32, 'sha512')
}

/**
 * Encrypt data using AES-256-GCM.
 * @param key The AES-256 key to use for encryption.
 * @param data The data which to encrypt.
 * @returns The encrypted data as a Buffer.
 * @throws Will throw an error if the encryption fails.
 */
export function encryptAes(key: Buffer, data: Buffer): Buffer {
  const iv = crypto.randomBytes(12) // 12 byte IV for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()])
  const authTag = cipher.getAuthTag()
  // IV (12) + AuthTag (16) + Ciphertext
  return Buffer.concat([iv, authTag, ciphertext])
}

/**
 * Decrypt data using AES-256-GCM.
 * @param key The AES-256 key to use for decryption.
 * @param data The encrypted data which to decrypt.
 * @returns The decrypted data as a Buffer.
 * @throws Will throw an error if the decryption fails.
 */
export function decryptAes(key: Buffer, data: Buffer): Buffer {
  const iv = data.subarray(0, 12) // 12 byte IV for GCM
  const authTag = data.subarray(12, 28) // 16 byte auth tag
  const ciphertext = data.subarray(28)
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}
