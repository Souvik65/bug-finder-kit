# Mobile Security Review — Technical Reference & MASVS Guide

## 1. OWASP MASVS v2.0 Control Mapping

The OWASP Mobile Application Security Verification Standard defines key focus areas:

| MASVS Domain | Security Focus | Primary Code Inspection Area |
|---|---|---|
| **MASVS-STORAGE** | Protection of sensitive data at rest | KeyStore, Keychain, SQLite cipher, Logcat scrub |
| **MASVS-CRYPTO** | Proven cryptographic algorithms & key generation | AES-GCM, RSA-OAEP, hardware-backed keys |
| **MASVS-AUTH** | Biometric and session authentication | BiometricPrompt, CryptoObject, token lifetime |
| **MASVS-NETWORK** | Network communication encryption & trust | Certificate pinning, TLS 1.3, NetworkSecurityConfig |
| **MASVS-PLATFORM** | Platform interaction, IPC, and WebViews | Manifest exports, permissions, WebSettings, Deep links |
| **MASVS-CODE** | Code quality, binary hardening, and obfuscation | R8 rules, symbols stripping, debuggable=false |
| **MASVS-RESILIENCE**| Tamper resistance and reverse-engineering defense | Frida detection, jailbreak/root heuristics |

---

## 2. Certificate Pinning SPKI Hash Extraction & Rotation Strategy

Pinning against the **Subject Public Key Information (SPKI)** hash rather than the leaf certificate
allows the certificate to be renewed without breaking application connectivity (as long as the
key pair remains the same).

### Generating SPKI Hashes via OpenSSL
```bash
# 1. Fetch the remote certificate
openssl s_client -servername api.example.com -connect api.example.com:443 </dev/null 2>/dev/null | \
  openssl x509 -pubkey -noout | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | \
  openssl enc -base64
# Output: k2NwhAeAnWhqTUYLUqdsqKEsnqohZsODTH7FsJLd4GY=
```

### Mandatory Pin Rotation Rule:
Always deploy with **at least two pins**:
1. **Primary Pin:** The current active SPKI hash.
2. **Backup Pin:** The public key of an offline backup key pair held in a cold vault. If the
   primary certificate is compromised or expires, the server can be cut over to the backup
   key without requiring an emergency mobile app store update.

---

## 3. iOS Keychain `kSecAccessControl` Biometric Binding

For high-security banking or authentication apps on iOS, bind sensitive keys directly to
Touch ID / Face ID hardware:

```swift
import Security
import LocalAuthentication

func createBiometricProtectedKey(account: String, secretData: Data) -> OSStatus {
    var error: Unmanaged<CFError>?
    
    // Require biometric authentication (Face ID / Touch ID) or device passcode
    guard let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.biometryCurrentSet, .userPresence],
        &error
    ) else {
        print("Failed to create access control: \(String(describing: error))")
        return errSecParam
    }

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: "com.example.auth",
        kSecValueData as String: secretData,
        kSecAttrAccessControl as String: accessControl
    ]

    SecItemDelete(query as CFDictionary)
    return SecItemAdd(query as CFDictionary, nil)
}
```

---

## 4. Android Hardware-Backed KeyStore Key Generation

Ensure keys are protected inside the device's hardware Secure Element / Trusted Execution Environment (TEE):

```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator

fun generateHardwareBackedSecretKey(keyAlias: String) {
    val keyGenerator = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES,
        "AndroidKeyStore"
    )

    val keySpec = KeyGenParameterSpec.Builder(
        keyAlias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setUserAuthenticationRequired(false) // Set to true if biometric auth is required
        .build()

    keyGenerator.init(keySpec)
    keyGenerator.generateKey()
}
```

---

## 5. Reverse Engineering & Frida Hooking Defenses

While dynamic reverse-engineering defenses can never completely stop a dedicated reverse engineer,
they raise the bar significantly against automated scraping and malware.

### R8 / ProGuard Obfuscation Rules (`proguard-rules.pro`)
```pro
# Enable aggressive optimization and obfuscation
-repackageclasses 'o'
-allowaccessmodification

# Strip verbose debug logs from compiled APK
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

# Keep native models required for serialization
-keepattributes Signature, *Annotation*
```

### Basic Anti-Tamper & Root Detection Checklist
- Check for common root binaries (`/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/system/app/Superuser.apk`).
- Check `Build.TAGS != null && Build.TAGS.contains("test-keys")`.
- On iOS, check if `/Applications/Cydia.app`, `/Library/MobileSubstrate/MobileSubstrate.dylib`, or `/bin/bash` exist.
- Verify app binary signatures dynamically against the known signing certificate hash.
