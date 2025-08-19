# Homebridge Secrets Storage

Homebridge provides a secure mechanism for storing sensitive values ("secrets") such as API keys, tokens, and passwords. This system is designed to keep secrets out of plaintext configuration files and persist them in an encrypted and secure fashion.

## How Secrets Are Stored

- **OS Keychain (Preferred):**
  - On macOS, Windows, and Linux, Homebridge will use the system's native keychain/credential manager to store encryption keys securely.
- **Internal Encrypted Storage (Fallback):**
  - If the OS keychain is unavailable, Homebridge encrypts secrets using AES-256-GCM and stores them in a file (`<plugin>-secrets.json.enc`) with strict file permissions (`0600`).
  - The encryption key is derived from the Homebridge instance's unique ID and bridge PIN.

## SecretStore API

Plugins and core code should use the `SecretStore` class to persist and retrieve secrets securely. **Do not store secrets directly in `config.json` or other plaintext files.**

### Example Usage

```ts
import { SecretStore } from './secretStore.js'

// These would be provided by your plugin context
declare const persistPath: string
declare const uniqueID: string
declare const pluginName: string

const store = new SecretStore(persistPath, uniqueID, pluginName)

// Store a secret
store.setSecret('apiKey', 'super-secret-value')

// Retrieve a secret
const apiKey = store.getSecret('apiKey')
console.log('Retrieved API key:', apiKey) // Use the retrieved key

// Delete a secret
store.deleteSecret('apiKey')
```

- `persistPath`: Path to the Homebridge persistent storage directory (e.g., `~/.homebridge/persist`).
- `uniqueID`: Unique identifier for the Homebridge instance (usually installation-specific).
- `pluginName`: Name of the plugin (used to namespace secrets).

## Best Practices

- **Never store sensitive values in `config.json`.**
- Use `SecretStore` for all API keys, tokens, passwords, and other secrets.
- Ensure the Homebridge bridge PIN is strong and not easily guessable.
- Do not share or back up secret files (`*-secrets.json.enc`) without proper protection.

## Migration

If you have secrets in your `config.json`, migrate them to the `SecretStore` and remove them from the config file.

## Security Notes

- Secrets are encrypted at rest using AES-256-GCM.
- Encryption keys are stored in the OS keychain when available, or derived from the bridge PIN and unique ID as a fallback.
- Secret files are written with permissions `0600` (owner read/write only).

For more details, see the source code in `src/secretStore.ts` and `src/keyChain.ts`.
