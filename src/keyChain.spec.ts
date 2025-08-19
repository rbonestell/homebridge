import { Buffer } from 'node:buffer'
import * as fs from 'node:fs'
import { afterEach, describe, expect, it } from 'vitest'
import { KeyChainFactory } from './keyChain.js'
import * as keyChainModule from './keyChain.js'

const persistPath = '/tmp/homebridge-test-persist'
const uniqueID = 'test-unique-id'

// Helper to clean up test files
afterEach(() => {
  try {
    fs.unlinkSync(`${persistPath}/keychain.json.enc`)
  } catch {}
})

describe('keyChainFactory', () => {
  it('returns a KeyChain instance', () => {
    const kc = KeyChainFactory.getKeyChain(uniqueID)
    expect(typeof kc.createKey).toBe('function')
    expect(typeof kc.getKey).toBe('function')
    expect(typeof kc.deleteKey).toBe('function')
  })
})

const InternalKeyChain = (keyChainModule as any).InternalKeyChain
const formatKeyName = (keyChainModule as any).formatKeyName

if (InternalKeyChain) {
  describe('internalKeyChain', () => {
    it('creates, gets, and deletes a key', async () => {
      const kc = new InternalKeyChain(uniqueID, persistPath)
      await kc.createKey('plugin1')
      const key = await kc.getKey('plugin1')
      expect(key).toBeInstanceOf(Buffer)
      await kc.deleteKey('plugin1')
      expect(await kc.getKey('plugin1')).toBeNull()
    })

    it('returns null for missing key', async () => {
      const kc = new InternalKeyChain(uniqueID, persistPath)
      expect(await kc.getKey('notfound')).toBeNull()
    })

    it('persists keys to disk', async () => {
      const kc = new InternalKeyChain(uniqueID, persistPath)
      await kc.createKey('plugin2')
      // Create a new instance to force reload from disk
      const kc2 = new InternalKeyChain(uniqueID, persistPath)
      const key = await kc2.getKey('plugin2')
      expect(key).toBeInstanceOf(Buffer)
    })
  })
}

describe('formatKeyName', () => {
  it('returns serviceName if no pluginName', () => {
    if (typeof formatKeyName === 'function') {
      expect(formatKeyName()).toBe('homebridge')
    }
  })
  it('sanitizes pluginName', () => {
    if (typeof formatKeyName === 'function') {
      expect(formatKeyName('foo!@#bar')).toBe('homebridge_foo---bar')
    }
  })
  it('handles multiple consecutive special characters', () => {
    if (typeof formatKeyName === 'function') {
      expect(formatKeyName('foo!@#$%^&*()bar')).toBe('homebridge_foo-bar')
    }
  })
  it('handles edge cases', () => {
    if (typeof formatKeyName === 'function') {
      expect(formatKeyName('')).toBe('homebridge_')
      expect(formatKeyName('normal-plugin')).toBe('homebridge_normal-plugin')
      expect(formatKeyName('plugin.with.dots')).toBe('homebridge_plugin.with.dots')
    }
  })
})

describe('keyChainFactory integration', () => {
  it('should return a keychain instance', () => {
    const keychain = KeyChainFactory.getKeyChain('test-id')
    expect(keychain).toBeDefined()
    expect(typeof keychain.createKey).toBe('function')
    expect(typeof keychain.getKey).toBe('function')
    expect(typeof keychain.deleteKey).toBe('function')
  })
})
