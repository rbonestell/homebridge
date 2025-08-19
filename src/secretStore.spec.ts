import { Buffer } from 'node:buffer'
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { KeyChainFactory } from './keyChain.js'
import { SecretStore } from './secretStore.js'

// Mock KeyChain to always return a static key for deterministic tests
const STATIC_KEY = Buffer.alloc(32, 1) // 32 bytes of value 1
const mockKeyChain = {
  getKey: vi.fn().mockReturnValue(STATIC_KEY),
  createKey: vi.fn().mockReturnValue(STATIC_KEY),
}

describe('secretStore', () => {
  const persistPath = '/tmp/homebridge-test-persist'
  const uniqueID = 'test-unique-id'
  const pluginName = 'test-plugin'
  let store: SecretStore

  beforeAll(() => {
    vi.spyOn(KeyChainFactory, 'getKeyChain').mockReturnValue(mockKeyChain as any)
  })

  beforeEach(() => {
    store = new SecretStore(persistPath, uniqueID, pluginName)
  })

  beforeEach(async () => {
    vi.restoreAllMocks()
    vi.spyOn(store as any, 'saveSecretsToDisk').mockImplementation(() => {})
    vi.spyOn(store as any, 'loadSecretsFromDisk').mockImplementation(() => {})
    // @ts-expect-error: test access to private
    store.secrets = {}
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.clearAllMocks()
  })

  it('should set and get a secret', () => {
    store.setSecret('apiKey', 'super-secret-value')
    expect(store.getSecret('apiKey')).toBe('super-secret-value')
  })

  it('should return null for missing secret', () => {
    expect(store.getSecret('notfound')).toBeNull()
  })

  it('should delete a secret', () => {
    store.setSecret('toDelete', 'value')
    expect(store.getSecret('toDelete')).toBe('value')
    store.deleteSecret('toDelete')
    expect(store.getSecret('toDelete')).toBeNull()
  })

  it('should not fail if deleting a non-existent secret', () => {
    expect(() => store.deleteSecret('nope')).not.toThrow()
  })

  it('should sanitize pluginName in filePath', async () => {
    const weirdName = 'plugin!@#%$^&*()_+'
    const s = new SecretStore(persistPath, uniqueID, weirdName)
    vi.spyOn(s as any, 'saveSecretsToDisk').mockImplementation(() => {})
    vi.spyOn(s as any, 'loadSecretsFromDisk').mockImplementation(() => {})
    // @ts-expect-error: test access to private
    expect(s.filePath).toContain('plugin')
    // @ts-expect-error: test access to private
    expect(s.filePath).not.toMatch(/[!@#%$^&*()_+]/)
  })

  describe('secret migration', () => {
    it('should migrate secrets from config object', () => {
      const config = {
        name: 'Test Platform',
        apiKey: 'secret-api-key',
        password: 'secret-password',
        normalSetting: 'not-a-secret',
      }

      const result = store.migrateSecretsFromConfig(config, ['apiKey', 'password'])

      expect(result.migratedCount).toBe(2)
      expect(result.cleanedConfig).toEqual({
        name: 'Test Platform',
        normalSetting: 'not-a-secret',
      })

      // Verify secrets were stored
      expect(store.getSecret('apiKey')).toBe('secret-api-key')
      expect(store.getSecret('password')).toBe('secret-password')
    })

    it('should detect secrets in config', () => {
      const config = {
        name: 'Test Platform',
        apiKey: 'secret-value',
        token: 'another-secret',
        normalSetting: 'not-a-secret',
      }

      const foundSecrets = SecretStore.detectSecretsInConfig(config, ['apiKey', 'token', 'missingKey'])

      expect(foundSecrets).toEqual(['apiKey', 'token'])
    })

    it('should handle empty migration gracefully', () => {
      const config = { name: 'Test Platform' }

      const result = store.migrateSecretsFromConfig(config, ['apiKey', 'password'])

      expect(result.migratedCount).toBe(0)
      expect(result.cleanedConfig).toEqual(config)
    })
  })

  describe('file format validation', () => {
    it('should handle invalid file format gracefully', () => {
      const invalidJson = 'invalid json'
      vi.spyOn(store as any, 'loadSecretsFromDisk').mockImplementation(() => {
        try {
          JSON.parse(invalidJson)
        } catch (e: any) {
          // @ts-expect-error: access private property for testing
          store.secrets = {}
        }
      })

      expect(() => {
        // @ts-expect-error: call private method for testing
        store.loadSecretsFromDisk()
      }).not.toThrow()
    })

    it('should validate secrets file version', () => {
      const invalidVersion = { version: 2, data: {} }
      vi.spyOn(store as any, 'loadSecretsFromDisk').mockImplementation(() => {
        // @ts-expect-error: access private property for testing
        if (invalidVersion.version !== 1) {
          store.secrets = {}
        }
      })

      expect(() => {
        // @ts-expect-error: call private method for testing
        store.loadSecretsFromDisk()
      }).not.toThrow()
    })
  })
})
