import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { decryptAes, encryptAes, generateAesKey } from './crypto.js'

describe('crypto', () => {
  describe('generateAesKey', () => {
    it('should generate a 32-byte key for given password and salt', () => {
      const password = Buffer.from('test-password')
      const salt = Buffer.from('test-salt')
      const key = generateAesKey(password, salt)
      expect(key).toBeInstanceOf(Buffer)
      expect(key.length).toBe(32)
    })
    it('should generate different keys for different salts', () => {
      const password = Buffer.from('test-password')
      const salt1 = Buffer.from('salt1')
      const salt2 = Buffer.from('salt2')
      const key1 = generateAesKey(password, salt1)
      const key2 = generateAesKey(password, salt2)
      expect(key1.equals(key2)).toBeFalsy()
    })
  })

  describe('encryptAes and decryptAes', () => {
    it('should encrypt and decrypt data correctly', () => {
      const password = Buffer.from('encryption-password')
      const salt = Buffer.from('encryption-salt')
      const key = generateAesKey(password, salt)
      const data = Buffer.from('Secret message!')
      const encrypted = encryptAes(key, data)
      expect(encrypted).toBeInstanceOf(Buffer)
      expect(encrypted.length).toBeGreaterThan(data.length)
      const decrypted = decryptAes(key, encrypted)
      expect(decrypted.equals(data)).toBeTruthy()
    })
    it('should throw if decrypting with wrong key', () => {
      const password = Buffer.from('password1')
      const salt = Buffer.from('salt1')
      const key1 = generateAesKey(password, salt)
      const key2 = generateAesKey(Buffer.from('password2'), salt)
      const data = Buffer.from('Another secret')
      const encrypted = encryptAes(key1, data)
      expect(() => decryptAes(key2, encrypted)).toThrow()
    })
    it('should throw if data is tampered', () => {
      const password = Buffer.from('password')
      const salt = Buffer.from('salt')
      const key = generateAesKey(password, salt)
      const data = Buffer.from('Sensitive data')
      const encrypted = encryptAes(key, data)
      // Tamper with ciphertext
      const tampered = Buffer.from(encrypted)
      tampered[tampered.length - 1] ^= 0xFF
      expect(() => decryptAes(key, tampered)).toThrow()
    })
  })
})
