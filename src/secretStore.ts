import { Buffer } from 'node:buffer'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { KeyChainFactory } from './keyChain.js'
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
      this.secrets = JSON.parse(raw)
    } catch (e: any) {
      console.error(`Failed to load secrets: ${e.message}`)
    }
  }

  /**
   * Save secrets to disk
   */
  private saveSecretsToDisk(): void {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.secrets, null, 2), { mode: 0o600 })
    } catch (e: any) {
      console.error(`Failed to save secrets: ${e.message}`)
    }
  }
}
