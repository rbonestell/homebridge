import { Buffer } from 'node:buffer'
import { execFileSync } from 'node:child_process'
import crypto, { randomUUID } from 'node:crypto'
import * as fs from 'node:fs'
import * as os from 'node:os'
import path from 'node:path/posix'
import { User } from './user.js'
import { decryptAes, encryptAes, generateAesKey } from './util/crypto.js'

const serviceName = 'homebridge'

/**
 * Formats the key name, optionally for a given plugin name.
 * @param pluginName The name of the plugin to for which to format the key name.
 * @returns The formatted key name.
 */
function formatKeyName(pluginName?: string): string {
  if (!pluginName) {
    return serviceName
  }
  // Replace any characters that are not alphanumeric, dot, or dash with a dash
  // This is to ensure the key name is safe for use in a file system or command line
  let sanitizedPluginName = pluginName.replace(/[^a-z0-9]/gi, '-')
  sanitizedPluginName = sanitizedPluginName.replace(/-+/g, '-')
  return `${serviceName}_${sanitizedPluginName}`
}

/**
 * Interface for a key store that supports async set, get, and delete operations.
 */
export interface KeyChain {
  /**
   * Creates and stores a new key.
   * This will overwrite an existing key.
   * @param pluginName The plugin name to namespace the key.
   */
  createKey: (pluginName?: string) => Buffer

  /**
   * Retrieves a value for a given key.
   * @returns The value if found, otherwise null.
   * @param pluginName The plugin name to namespace the key.
   */
  getKey: (pluginName?: string) => Buffer | null

  /**
   * Deletes a key.
   * @param pluginName The plugin name to namespace the key.
   */
  deleteKey: (pluginName?: string) => void
}

interface InternalKeyChainFileFormat {
  version: 1
  data: Map<string, string>
}

export class KeyChainFactory {
  public static getKeyChain(uniqueID: string): KeyChain {
    if (SystemKeyChain.isAvailable()) {
      return new SystemKeyChain()
    } else {
      return new InternalKeyChain(uniqueID, User.storagePath())
    }
  }
}

class InternalKeyChain implements KeyChain {
  private readonly store: Map<string, string>
  private readonly internalKey: Buffer
  private bridgePin: string
  private filePath: string

  constructor(bridgePin: string, storagePath: string) {
    this.bridgePin = bridgePin
    this.filePath = path.join(storagePath, 'keychain.json.enc')
    this.internalKey = generateAesKey(Buffer.from(bridgePin), Buffer.from(serviceName))
    this.store = this.loadKeyStoreFromDisk()
  }

  createKey(pluginName?: string): Buffer {
    const newKey = generateAesKey(Buffer.from(this.bridgePin), Buffer.from(formatKeyName(pluginName)))
    const encryptedValue = encryptAes(this.internalKey, newKey)
    this.store.set(formatKeyName(pluginName), encryptedValue.toString('base64'))
    this.saveKeyStoreToDisk()
    return newKey
  }

  getKey(pluginName?: string): Buffer | null {
    const keyString = this.store.get(formatKeyName(pluginName)) ?? null
    if (keyString) {
      const encryptedKey = Buffer.from(keyString, 'base64')
      const decryptedKey = decryptAes(this.internalKey, encryptedKey)
      return decryptedKey
    }
    return null
  }

  deleteKey(pluginName?: string): void {
    this.store.delete(formatKeyName(pluginName))
    this.saveKeyStoreToDisk()
  }

  /**
   * Loads the secrets from disk into memory.
   * If the file does not exist, it initializes an empty store.
   */
  private loadKeyStoreFromDisk(): Map<string, string> {
    if (!fs.existsSync(this.filePath)) {
      return new Map()
    }
    const data = fs.readFileSync(this.filePath, 'utf8')
    const internalSecretsFile: InternalKeyChainFileFormat = JSON.parse(data)

    return new Map(Object.entries(internalSecretsFile.data))
  }

  /**
   * Saves the current state of the secret store to disk atomically.
   * Writes to a temporary file first, then renames it to the final destination.
   */
  private saveKeyStoreToDisk(): void {
    // Generate a unique temporary file path in the same directory as the target file
    // Using the same directory helps ensure fs.rename is an atomic operation on most filesystems
    const tempFileName = `${path.basename(this.filePath)}.${randomUUID()}.tmp`
    const tempFilePath = path.join(path.dirname(this.filePath), tempFileName)

    // Convert the Map to a plain JavaScript object for JSON compatibility.
    const dataToSerialize = {
      version: 1,
      data: Object.fromEntries(this.store),
    }
    const fileContent = JSON.stringify(dataToSerialize, null, 2)

    try {
      // Write data to a temporary file with secure permissions (owner read/write only)
      fs.writeFileSync(tempFilePath, fileContent, { mode: 0o600, encoding: 'utf8' })

      // Atomically rename the temporary file to the final destination file.
      // This overwrites the original file if it exists.
      fs.renameSync(tempFilePath, this.filePath)
    } catch (error) {
      console.error('Failed to save secrets atomically:', error)
      // If an error occurs (e.g., during write or rename), attempt to clean up the temporary file
      try {
        fs.unlinkSync(tempFilePath)
      } catch (cleanupError: any) {
        // Ignore error if the temporary file doesn't exist (e.g., if writeFile failed)
        if (cleanupError.code !== 'ENOENT') {
          console.error('Failed to clean up temporary secrets file:', cleanupError)
        }
      }
      // Re-throw the original error to signal that the save operation failed
      throw error
    }
  }
}

/**
 * Cross-platform secure keychain implementation for storing keys using OS-native tools.
 * Supports macOS (security), Windows (cmdkey/PowerShell), and Linux (secret-tool).
 */
class SystemKeyChain implements KeyChain {
  private systemOS: string

  /**
   * Creates a new SystemKeyChain instance.
   */
  constructor() {
    if (!SystemKeyChain.isAvailable()) {
      throw new Error('No supported keychain backend available on this platform.')
    }
    this.systemOS = os.platform()
  }

  /**
   * Checks if a supported keychain backend is available on the current platform.
   * Note: Fallback to use `InternalKeyChain` if `SystemKeyChain` not available.
   * @returns True if available, false otherwise.
   */
  static isAvailable(): boolean {
    const platform = os.platform()
    if (platform === 'darwin') {
      return fs.existsSync('/usr/bin/security')
    } else if (platform === 'win32') {
      return this.isPowerShellAvailable()
    } else if (platform === 'linux') {
      return this.isCommandAvailable('secret-tool')
    }
    return false
  }

  /**
   * Creates a new randomized AES key and stores it in the OS keychain.
   * @param pluginName The name of the plugin to which they key belongs, if any.
   */
  createKey(pluginName?: string): Buffer {
    const newKey = generateAesKey(Buffer.from(crypto.randomUUID()), Buffer.from(crypto.randomUUID()))
    const args = this.getSetCommand(formatKeyName(pluginName), newKey.toString('base64'))
    execFileSync(args.command, args.args, { timeout: 5000 })
    return newKey
  }

  /**
   * Retrieves a value for a given key from the OS keychain.
   * @param pluginName The name of the plugin to which the key belongs, if any.
   * @returns The value if found, otherwise null.
   */
  getKey(pluginName?: string): Buffer | null {
    try {
      const args = this.getGetCommand(formatKeyName(pluginName))
      const keyData = execFileSync(args.command, args.args, { timeout: 5000 })
      return keyData ?? null
    } catch (err: any) {
      if (err.status === 44 || err.status === 1) {
        return null
      }
      throw err
    }
  }

  /**
   * Deletes a key-value pair from the OS keychain.
   * @param pluginName The name of the plugin to which they key belongs, if any.
   */
  deleteKey(pluginName?: string): void {
    const args = this.getDeleteCommand(formatKeyName(pluginName))
    execFileSync(args.command, args.args, { timeout: 5000 })
  }

  /**
   * Gets the command and arguments for setting a key-value pair, based on platform.
   * @param value The value to store.
   * @returns The command, arguments, and optional input for the child process.
   * @throws Error if the platform is unsupported.
   */
  private getSetCommand(value: string, keyName: string): { command: string, args: string[], input?: string } {
    if (this.systemOS === 'darwin') {
      return {
        command: '/usr/bin/security',
        args: ['add-generic-password', '-a', keyName, '-s', serviceName, '-w', value, '-U'],
      }
    } else if (this.systemOS === 'win32') {
      return {
        command: 'powershell.exe',
        args: ['-Command', `cmdkey /generic:"${keyName}" /user:"${keyName}" /pass:"${value}"`],
      }
    } else if (this.systemOS === 'linux') {
      return {
        command: 'secret-tool',
        args: ['store', '--label', `Homebridge secrets key for ${keyName}`, 'service', keyName, 'account', 'homebridge'],
        input: value,
      }
    } else {
      throw new Error(`Unsupported platform: ${this.systemOS}`)
    }
  }

  /**
   * Gets the command and arguments for retrieving a key's value, based on platform.
   * @returns The command and arguments for the child process.
   * @throws Error if the platform is unsupported.
   */
  private getGetCommand(keyName: string): { command: string, args: string[] } {
    if (this.systemOS === 'darwin') {
      return {
        command: '/usr/bin/security',
        args: ['find-generic-password', '-a', keyName, '-s', serviceName, '-w'],
      }
    } else if (this.systemOS === 'win32') {
      // Use cmdkey to retrieve stored credentials on Windows
      // This avoids the interactive Get-Credential prompt
      return {
        command: 'powershell.exe',
        args: ['-Command', `$cred = cmdkey /list:"${keyName}" 2>$null; if ($LASTEXITCODE -eq 0) { (cmdkey /list:"${keyName}" | Select-String "Password:").Line.Split(":")[1].Trim() } else { throw "Credential not found" }`],
      }
    } else if (this.systemOS === 'linux') {
      return {
        command: 'secret-tool',
        args: ['lookup', 'service', keyName, 'account', 'homebridge'],
      }
    } else {
      throw new Error(`Unsupported platform: ${this.systemOS}`)
    }
  }

  /**
   * Gets the command and arguments for deleting a key, based on platform.
   * @returns The command and arguments for the child process.
   * @throws Error if the platform is unsupported.
   */
  private getDeleteCommand(keyName: string): { command: string, args: string[] } {
    if (this.systemOS === 'darwin') {
      return {
        command: '/usr/bin/security',
        args: ['delete-generic-password', '-a', keyName, '-s', serviceName],
      }
    } else if (this.systemOS === 'win32') {
      return {
        command: 'powershell.exe',
        args: ['-Command', `cmdkey /delete:"${keyName}"`],
      }
    } else if (this.systemOS === 'linux') {
      // On Linux, clear the stored secret
      return {
        command: 'secret-tool',
        args: ['clear', 'service', keyName, 'account', 'homebridge'],
      }
    } else {
      throw new Error(`Unsupported platform: ${this.systemOS}`)
    }
  }

  /**
   * Checks if a command is available in the system PATH.
   * @param command The command to check.
   * @returns True if available, false otherwise.
   */
  private static isCommandAvailable(command: string): boolean {
    try {
      execFileSync('which', [command], { stdio: 'ignore' })
      return true
    } catch {
      return false
    }
  }

  /**
   * Checks if PowerShell is available on Windows.
   * @returns True if PowerShell is available, false otherwise.
   */
  private static isPowerShellAvailable(): boolean {
    try {
      execFileSync('powershell.exe', ['-Command', '$PSVersionTable.PSVersion'], { stdio: 'ignore' })
      return true
    } catch {
      return false
    }
  }
}
