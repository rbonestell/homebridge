/* eslint-disable node/prefer-global/buffer */
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'

type Aes256Key = Buffer

export interface SecretsFileFormat {
  version: 1
  data: Record<string, string>
}

export class SecretStore {
  private readonly filePath: string
  private readonly baseKey: Aes256Key
  private readonly pluginName: string
  private secrets: Record<string, string>

  constructor(persistPath: string, uniqueID: string, pluginName: string) {
    this.pluginName = pluginName.replace(/[^a-z0-9.-]/gi, '')
    this.filePath = path.join(persistPath, `${this.pluginName}-secrets.json.enc`)
    this.baseKey = this.deriveBaseKey(persistPath, uniqueID)
    this.secrets = {}

    this.loadSecretsFromDisk()
  }

  private deriveBaseKey(persistPath: string, uniqueID: string): Buffer {
    const persistPathHash = crypto.createHash('sha256').update(persistPath).digest('hex')
    const hostname = os.hostname()
    const machineId = this.getMachineId()

    const saltMaterial = `${uniqueID}:${persistPathHash}:${hostname}:${machineId}`
    return crypto.pbkdf2Sync(
      saltMaterial,
      'homebridge-secret-store-v1', // static salt
      250_000,
      32,
      'sha512',
    )
  }

  private getMachineId(): string {
    try {
      if (fs.existsSync('/etc/machine-id')) {
        return fs.readFileSync('/etc/machine-id', 'utf8').trim()
      }
      if (fs.existsSync('/var/db/uuid')) {
        return fs.readFileSync('/var/db/uuid', 'utf8').trim()
      }
    } catch (e) {
      // ignore and fallback
    }
    return crypto.createHash('sha256').update(os.hostname()).digest('hex')
  }

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

  private saveSecretsToDisk(): void {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.secrets, null, 2), { mode: 0o600 })
    } catch (e: any) {
      console.error(`Failed to save secrets: ${e.message}`)
    }
  }

  private derivePluginKey(): Buffer {
    return crypto.pbkdf2Sync(
      `${this.baseKey.toString('hex')}:${this.pluginName}`,
      'homebridge-plugin-secret-salt-v1',
      250_000,
      32,
      'sha512',
    )
  }

  private encrypt(pluginKey: Buffer, plaintext: string): string {
    if (pluginKey.length !== 32) {
      throw new Error('Invalid key length for AES-256-GCM (expected 32 bytes)')
    }
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', pluginKey, iv)

    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ])
    const authTag = cipher.getAuthTag()
    const payload = Buffer.concat([iv, encrypted, authTag])
    return payload.toString('base64')
  }

  private decrypt(pluginKey: Buffer, base64Encrypted: string): string {
    if (pluginKey.length !== 32) {
      throw new Error('Invalid key length for AES-256-GCM (expected 32 bytes)')
    }

    const payload = Buffer.from(base64Encrypted, 'base64')
    const iv = payload.slice(0, 12)
    const authTag = payload.slice(payload.length - 16)
    const ciphertext = payload.slice(12, payload.length - 16)

    const decipher = crypto.createDecipheriv('aes-256-gcm', pluginKey, iv)
    decipher.setAuthTag(authTag)

    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ])
    return decrypted.toString('utf8')
  }

  /**
   * Store a secret value under this plugin
   */
  public setSecret(secretName: string, plaintextValue: string): void {
    const pluginKey = this.derivePluginKey()
    const encryptedValue = this.encrypt(pluginKey, plaintextValue)

    if (!this.secrets) {
      this.secrets = {}
    }
    this.secrets[secretName] = encryptedValue
    this.saveSecretsToDisk()
  }

  /**
   * Load a secret value under this plugin
   */
  public getSecret(secretName: string): string | null {
    const pluginSecrets = this.secrets
    if (!pluginSecrets) {
      return null
    }
    const encryptedValue = pluginSecrets[secretName]
    if (!encryptedValue) {
      return null
    }
    const pluginKey = this.derivePluginKey()
    return this.decrypt(pluginKey, encryptedValue)
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
}
