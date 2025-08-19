import { Buffer } from 'node:buffer'
import { randomUUID } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { KeyChainFactory } from './keyChain.js'
import { Logger } from './logger.js'
import { decryptAes, encryptAes } from './util/crypto.js'

export interface SecretsFileFormat {
  version: 1
  data: Record<string, string>
}

export class SecretStore {
  private readonly filePath: string
  private readonly pluginName: string
  private secrets: Record<string, string>
  private baseKey!: Buffer

  constructor(persistPath: string, uniqueID: string, pluginName: string) {
    this.pluginName = pluginName.replace(/[^a-z0-9]/gi, '-')
    this.filePath = path.join(persistPath, `${this.pluginName}-secrets.json.enc`)
    this.secrets = {}
    this.baseKey = this.getOrCreateSecretEncryptionKey(uniqueID)
    this.loadSecretsFromDisk()
  }

  /**
   * Store a secret value under this plugin
   */
  public setSecret(secretName: string, plaintextValue: string): void {
    const encryptedValue = encryptAes(this.baseKey, Buffer.from(plaintextValue, 'utf8'))

    if (!this.secrets) {
      this.secrets = {}
    }
    this.secrets[secretName] = encryptedValue.toString('base64')
    this.saveSecretsToDisk()
  }

  /**
   * Load a secret value under this plugin
   */
  public getSecret(secretName: string): string | null {
    if (!this.secrets) {
      return null
    }
    const encryptedValue = this.secrets[secretName]
    if (!encryptedValue) {
      return null
    }
    const decryptedValue = decryptAes(this.baseKey, Buffer.from(encryptedValue, 'base64'))
    return decryptedValue.toString('utf8')
  }

  /**
   * Delete a secret value under this plugin
   */
  public deleteSecret(secretName: string): void {
    const pluginSecrets = this.secrets
    if (pluginSecrets && pluginSecrets[secretName]) {
      delete pluginSecrets[secretName]
      this.saveSecretsToDisk()
    }
  }

  /**
   * Migrate secrets from a plaintext configuration object to encrypted storage
   * This is intended to help migrate secrets from config.json to secure storage
   * @param configObject The configuration object that may contain secrets
   * @param secretKeys Array of keys that should be treated as secrets and migrated
   * @returns Object with migrated secrets removed and a count of migrated secrets
   */
  public migrateSecretsFromConfig(configObject: Record<string, any>, secretKeys: string[]): { cleanedConfig: Record<string, any>, migratedCount: number } {
    const cleanedConfig = { ...configObject }
    let migratedCount = 0

    for (const key of secretKeys) {
      if (cleanedConfig[key] && typeof cleanedConfig[key] === 'string') {
        // Store the secret value
        this.setSecret(key, cleanedConfig[key])

        // Remove from the config
        delete cleanedConfig[key]
        migratedCount++

        Logger.internal.info(`Migrated secret '${key}' for plugin ${this.pluginName} from config to secure storage`)
      }
    }

    return { cleanedConfig, migratedCount }
  }

  /**
   * Check if secrets exist that should be migrated from config
   * @param configObject The configuration object to check
   * @param secretKeys Array of keys that should be treated as secrets
   * @returns Array of secret keys found in the config that should be migrated
   */
  public static detectSecretsInConfig(configObject: Record<string, any>, secretKeys: string[]): string[] {
    const foundSecrets: string[] = []

    for (const key of secretKeys) {
      if (configObject[key] && typeof configObject[key] === 'string') {
        foundSecrets.push(key)
      }
    }

    return foundSecrets
  }

  /**
   * Get or create a secret encryption key using KeyChainFactory
   * @param uniqueID Installation-unique identifier which to use in key derivation
   * @returns A Buffer containing the secret encryption key
   */
  private getOrCreateSecretEncryptionKey(uniqueID: string): Buffer {
    const keyChain = KeyChainFactory.getKeyChain(uniqueID)
    const key = keyChain.getKey(this.pluginName) ?? keyChain.createKey(this.pluginName)
    return key
  }

  /**
   * Load secrets from disk if the secrets file exists
   */
  private loadSecretsFromDisk(): void {
    if (!fs.existsSync(this.filePath)) {
      return
    }
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8')
      const secretsFile: SecretsFileFormat = JSON.parse(raw)

      // Validate file format
      if (!secretsFile.version || secretsFile.version !== 1) {
        Logger.internal.warn(`Invalid secrets file format version for plugin ${this.pluginName}. Expected version 1, got ${secretsFile.version}`)
        this.secrets = {}
        return
      }

      if (!secretsFile.data || typeof secretsFile.data !== 'object') {
        Logger.internal.warn(`Invalid secrets file data format for plugin ${this.pluginName}`)
        this.secrets = {}
        return
      }

      this.secrets = secretsFile.data
    } catch (e: any) {
      Logger.internal.error(`Failed to load secrets for plugin ${this.pluginName}: ${e.message}`)
      this.secrets = {}
    }
  }

  /**
   * Save secrets to disk with atomic operations
   */
  private saveSecretsToDisk(): void {
    // Generate a unique temporary file path in the same directory as the target file
    // Using the same directory helps ensure fs.rename is an atomic operation on most filesystems
    const tempFileName = `${path.basename(this.filePath)}.${randomUUID()}.tmp`
    const tempFilePath = path.join(path.dirname(this.filePath), tempFileName)

    const secretsFile: SecretsFileFormat = {
      version: 1,
      data: this.secrets || {},
    }

    const fileContent = JSON.stringify(secretsFile, null, 2)

    try {
      // Write data to a temporary file with secure permissions (owner read/write only)
      fs.writeFileSync(tempFilePath, fileContent, { mode: 0o600, encoding: 'utf8' })

      // Atomically rename the temporary file to the final destination file.
      // This overwrites the original file if it exists.
      fs.renameSync(tempFilePath, this.filePath)
    } catch (error: any) {
      Logger.internal.error(`Failed to save secrets for plugin ${this.pluginName}: ${error.message}`)
      // If an error occurs (e.g., during write or rename), attempt to clean up the temporary file
      try {
        fs.unlinkSync(tempFilePath)
      } catch (cleanupError: any) {
        // Ignore error if the temporary file doesn't exist (e.g., if writeFile failed)
        if (cleanupError.code !== 'ENOENT') {
          Logger.internal.error(`Failed to clean up temporary secrets file for plugin ${this.pluginName}: ${cleanupError.message}`)
        }
      }
      // Re-throw the original error to signal that the save operation failed
      throw error
    }
  }
}
