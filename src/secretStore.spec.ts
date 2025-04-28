import { Buffer } from 'node:buffer'
import * as path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { SecretStore } from './secretStore.js'

describe('secretStore', () => {
  const persistPath = '/tmp/homebridge-test-persist'
  const uniqueID = 'test-unique-id'
  const pluginName = 'test-plugin'
  let store: SecretStore

  beforeEach(() => {
    // Mock the private disk IO methods to no-ops
    store = new SecretStore(persistPath, uniqueID, pluginName)
    vi.spyOn(store, 'saveSecretsToDisk' as any).mockImplementation(() => {})
    vi.spyOn(store, 'loadSecretsFromDisk' as any).mockImplementation(() => {})
    // Reset secrets to empty for each test
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

  it('should throw if pluginKey is wrong length', () => {
    // Patch derivePluginKey to return wrong length
    vi.spyOn(store as any, 'derivePluginKey').mockReturnValue(Buffer.alloc(16))
    expect(() => store.setSecret('bad', 'value')).toThrow()
    // @ts-expect-error: test access to private
    store.secrets.bad = 'invalid'
    expect(() => store.getSecret('bad')).toThrow()
  })

  it('should sanitize pluginName in filePath', () => {
    const weirdName = 'plugin!@#%$^&*()_+'
    const s = new SecretStore(persistPath, uniqueID, weirdName)
    vi.spyOn(s, 'saveSecretsToDisk' as any).mockImplementation(() => {})
    vi.spyOn(s, 'loadSecretsFromDisk' as any).mockImplementation(() => {})
    // @ts-expect-error: test access to private
    expect(s.filePath).toContain('plugin')
    // @ts-expect-error: test access to private
    expect(s.filePath).not.toMatch(/[!@#%$^&*()_+]/)
  })
})
