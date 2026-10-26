---
name: mobile-security-review
description: >
  Comprehensive iOS and Android mobile application security audit skill. Evaluates native
  and hybrid (React Native, Flutter, Swift, Kotlin, Java) apps for mobile-specific
  vulnerabilities: insecure local storage (unencrypted SharedPreferences, UserDefaults,
  SQLite databases), missing or broken SSL/TLS certificate pinning, deep link and custom
  URL scheme abuse, insecure WebView settings (JavaScript bridges, file:// scheme access),
  exported Android components (activities, services, broadcast receivers), and screen
  snapshot caching. Activate when the user asks to "audit mobile security", "iOS security review",
  "Android security audit", "certificate pinning check", "WebView security audit", "deep link vulnerability",
  "exported component review", or "mobile app penetration test".
triggers:
  - "mobile security review"
  - "iOS security audit"
  - "Android security audit"
  - "certificate pinning"
  - "WebView security"
  - "deep link security"
  - "exported components"
  - "insecure local storage"
  - "Keychain audit"
  - "SharedPreferences security"
  - "mobile app penetration test"
  - "OWASP MASVS"
  - "React Native security"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[mobile-security, ios-security, android-security, keychain, sharedpreferences, certificate-pinning, deep-links, webview-security, exported-components, owasp-masvs]"
date_added: "2026-10-23"
---

# Mobile Application Security Review (iOS & Android)

> Mobile applications execute on untrusted, user-controlled client hardware. Attackers have
> direct physical access to device storage, memory debuggers, proxy interceptors (Burp Suite,
> mitmproxy), and dynamic instrumentation frameworks (Frida, Objection).
>
> This skill provides an exhaustive code-level security audit methodology covering the
> **OWASP Mobile Application Security Verification Standard (MASVS)** across native (Swift,
> Kotlin, Java) and cross-platform (React Native, Flutter) mobile codebases.

---

## Mobile Attack Surface Taxonomy (OWASP MASVS)

```
Mobile Application Security Attack Surface
  ├── 1. Data Storage & Privacy (MASVS-STORAGE)
  │     ├── Plaintext SharedPreferences / UserDefaults storing tokens
  │     ├── Unencrypted SQLite / Realm / Room databases on internal storage
  │     ├── Sensitive data cached in system logs (Logcat, NSLog)
  │     └── Sensitive data exposed in background app switcher snapshots
  ├── 2. Network Communication (MASVS-NETWORK)
  │     ├── Missing or bypassed SSL/TLS certificate pinning
  │     ├── Insecure Network Security Config (trusting user CA certificates)
  │     └── Disabling ATS (NSAppTransportSecurity -> NSAllowsArbitraryLoads)
  ├── 3. Inter-Process Communication & Deep Links (MASVS-IPC)
  │     ├── Exported Android activities, services, receivers missing permissions
  │     ├── Deep link URL parameter injection (custom URI schemes vs App/Universal Links)
  │     └── Implicit intent hijacking and intent redirection flaws
  ├── 4. WebView & Dynamic Execution (MASVS-CODE)
  │     ├── Insecure addJavascriptInterface exposure allowing RCE on older devices
  │     ├── Enabled setAllowFileAccess / setAllowUniversalAccessFromFileURLs
  │     └── Loading untrusted HTTP URLs inside privileged WebViews
  └── 5. Resiliency & Reverse Engineering (MASVS-RESILIENCE)
        ├── Disabled code obfuscation / minification (R8 / ProGuard missing)
        ├── Lack of root / jailbreak detection for high-risk financial apps
        └── Hardcoded secrets, staging credentials, and private keys in APK/IPA
```

---

## Phase 1: Insecure Local Storage & Sensitive Data

Mobile apps frequently store authentication tokens, PII, or encryption keys in plaintext
storage locations easily readable via file-system explorers, device backups, or root access.

### 1. Android: `SharedPreferences` vs `EncryptedSharedPreferences`

```kotlin
// ❌ VULNERABLE: Plaintext SharedPreferences (stored as cleartext XML in /data/data/<pkg>/shared_prefs/)
val prefs = context.getSharedPreferences("user_session", Context.MODE_PRIVATE)
prefs.edit().putString("auth_token", jwtToken).apply()

// ✅ SAFE: Use AndroidX Security EncryptedSharedPreferences (AES-256 GCM backed by Android KeyStore)
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val securePrefs = EncryptedSharedPreferences.create(
    context,
    "secure_session",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
securePrefs.edit().putString("auth_token", jwtToken).apply()
```

### 2. iOS: `UserDefaults` vs `Keychain Services`

```swift
// ❌ VULNERABLE: UserDefaults is stored as unencrypted plist files in app sandbox
UserDefaults.standard.set(userPassword, forKey: "saved_password")

// ✅ SAFE: Use the iOS Keychain with strict accessibility controls
import Security

func saveToKeychain(service: String, account: String, data: Data) -> OSStatus {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecValueData as String: data,
        // Accessible only when device is unlocked, not included in unencrypted backups
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemDelete(query as CFDictionary)
    return SecItemAdd(query as CFDictionary, nil)
}
```

### 3. Screen Caching / Background Snapshots
When an app moves to the background, iOS and Android take a screenshot of the current view
for the app switcher multitasking view. If displaying account numbers, credit cards, or medical data:

- **Android:** Set `window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)` in `onCreate()`.
- **iOS:** Add an overlay or blur view in `applicationDidEnterBackground()` in `AppDelegate.swift` or `sceneDidEnterBackground()`.

---

## Phase 2: Transport Security & Certificate Pinning

Attackers use proxy tools (Burp Suite, Charles) with custom CA certificates installed on test
devices to inspect and tamper with API traffic. High-security apps must enforce **Certificate Pinning**.

### 1. Android: `network_security_config.xml`

```xml
<!-- ❌ VULNERABLE: Trusting user-installed certificates in production -->
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" /> <!-- Allows MITM proxying! -->
        </trust-anchors>
    </base-config>
</network-security-config>

<!-- ✅ SAFE: Trust only system CAs and pin SPKI hashes for production domain -->
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-01-01">
            <!-- SHA-256 hash of subject public key info -->
            <pin digest="SHA-256">k2NwhAeAnWhqTUYLUqdsqKEsnqohZsODTH7FsJLd4GY=</pin>
            <!-- Backup pin for certificate rotation -->
            <pin digest="SHA-256">r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByiboA58=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

### 2. OkHttp (Android / Kotlin) Certificate Pinning
```kotlin
// ✅ SAFE: OkHttp CertificatePinner
val certificatePinner = CertificatePinner.Builder()
    .add("api.example.com", "sha256/k2NwhAeAnWhqTUYLUqdsqKEsnqohZsODTH7FsJLd4GY=")
    .add("api.example.com", "sha256/r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByiboA58=")
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build()
```

---

## Phase 3: Deep Link & Custom URL Scheme Validation

Deep links allow external apps or web browsers to invoke specific screens in your app.

### 1. Custom URL Schemes (`myapp://`) vs Universal / App Links
- **Risk:** Custom URL schemes (`myapp://checkout?amount=100`) can be registered by **any** rogue app
  on the device! There is no domain ownership verification.
- **Remediation:** Always prefer **Android App Links** (verified via `assetlinks.json`) and
  **iOS Universal Links** (verified via `apple-app-site-association`).

### 2. Deep Link Parameter Validation
Never perform sensitive actions (transfers, deletions, account changes) directly from a deep link
without secondary explicit user confirmation.

```kotlin
// ❌ VULNERABLE: Executing sensitive action directly from deep link parameters
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val data: Uri? = intent?.data
    if (data?.scheme == "myapp" && data.host == "transfer") {
        val target = data.getQueryParameter("to")
        val amount = data.getQueryParameter("amount")
        // Executes transfer without user confirmation!
        executeTransfer(target, amount)
    }
}
```

---

## Phase 4: WebView Security & JavaScript Bridges

WebViews allow mobile apps to embed web content. Misconfigured WebViews can permit remote code
execution or local file access.

### 1. Insecure JavaScript Interface Exposure
```java
// ❌ CRITICAL VULNERABILITY: addJavascriptInterface on untrusted web content
WebView webView = findViewById(R.id.webview);
webView.getSettings().setJavaScriptEnabled(true);
// Bridges native Android methods to window.AndroidBridge in JS!
webView.addJavascriptInterface(new NativeWebAppInterface(this), "AndroidBridge");
// If untrusted external URL is loaded, XSS leads directly to Native Code Execution!
webView.loadUrl("https://untrusted-partner.example.com");
```

### 2. WebView Hardening Settings

```kotlin
// ✅ SAFE: Hardened WebView configuration
val webView = findViewById<WebView>(R.id.webview)
webView.settings.apply {
    javaScriptEnabled = false // Disable JS unless strictly required
    allowFileAccess = false   // Block file:// access
    allowContentAccess = false
    setSupportMultipleWindows(false)
    mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
}
```

---

## Phase 5: Android Component Exposure (`AndroidManifest.xml`)

In Android, components (`<activity>`, `<service>`, `<receiver>`, `<provider>`) are public to all
other apps on the device if `android:exported="true"` (or if they declare an `<intent-filter>`).

```xml
<!-- ❌ VULNERABLE: Debug / Internal activity exposed to other apps without permission -->
<activity 
    android:name=".InternalAdminActivity"
    android:exported="true"> <!-- Any app on device can launch this! -->
</activity>

<!-- ❌ VULNERABLE: ContentProvider vulnerable to path traversal -->
<provider
    android:name=".FileContentProvider"
    android:authorities="com.example.provider"
    android:exported="true" />

<!-- ✅ SAFE: Internal component explicitly un-exported -->
<activity 
    android:name=".InternalAdminActivity"
    android:exported="false" />

<!-- ✅ SAFE: Exported component protected by custom permission -->
<activity 
    android:name=".PartnerShareActivity"
    android:exported="true"
    android:permission="com.example.permission.PARTNER_SHARE" />
```

---

## Phase 6: Multi-Platform Hybrid Framework Security

### React Native
- **AsyncStorage is Insecure:** `AsyncStorage` stores data in unencrypted SQLite/XML.
  Never store auth tokens in `AsyncStorage`. Use `react-native-keychain` or `react-native-encrypted-storage`.
- **Debug Bridges:** Ensure `__DEV__` code branches and Flipper / React Native DevTools are stripped in release builds.

### Flutter
- **SharedPreferences is Plaintext:** Flutter's `shared_preferences` package is not encrypted.
  Use `flutter_secure_storage` (which uses KeyStore on Android and Keychain on iOS).

---

## Phase 7: Automated Mobile Code Scanning Script

Execute this PowerShell script across your mobile repository to discover common vulnerabilities:

```powershell
# PowerShell Mobile Security Auditor
Write-Host "=== Scanning Android Manifest for Insecure Exported Components ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include AndroidManifest.xml | Select-String -Pattern 'android:exported=["'']true["'']' | Select-Object Path, LineNumber, Line

Write-Host "`n=== Scanning for Insecure Plaintext Storage ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include *.kt,*.java,*.swift,*.ts,*.js | Select-String -Pattern "getSharedPreferences|UserDefaults\.standard|AsyncStorage\.setItem" | Select-Object Path, LineNumber, Line

Write-Host "`n=== Scanning for Insecure WebView Settings ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include *.kt,*.java | Select-String -Pattern "addJavascriptInterface|setAllowFileAccess\(true\)|setAllowUniversalAccessFromFileURLs" | Select-Object Path, LineNumber, Line

Write-Host "`n=== Scanning for Missing FLAG_SECURE on Windows ===" -ForegroundColor Cyan
Get-ChildItem -Recurse -Include *.kt,*.java | Select-String -Pattern "FLAG_SECURE" | Select-Object Path, LineNumber, Line
```

---

## Phase 8: Finding Template & Remediation Checklist

### Finding Template
```markdown
### [VULN-MOBILE-001] Exported Activity Accessible to Third-Party Apps Without Permission

- **Severity:** High
- **Platform:** Android
- **Location:** `app/src/main/AndroidManifest.xml:42` (`com.example.app.DebugSettingsActivity`)
- **Flaw Description:** The `DebugSettingsActivity` has `android:exported="true"` declared with no
  protecting `android:permission`. Any third-party application installed on the user's device can
  craft an implicit or explicit Intent to launch this activity, allowing unauthorized users to
  modify internal API staging URLs, toggle feature flags, and dump diagnostic logs.
- **Evidence / Code:**
  ```xml
  <activity android:name=".DebugSettingsActivity" android:exported="true" />
  ```
- **Remediation:**
  1. Set `android:exported="false"` if this activity is only intended for internal application use.
  2. If the activity must be invoked externally, protect it with a signature-level permission (`android:protectionLevel="signature"`).
  3. Strip debug activities completely from production release builds using build variants.
- **Confidence:** High
```

### Remediation Checklist
- [ ] Migrate sensitive storage from `SharedPreferences` / `UserDefaults` to `EncryptedSharedPreferences` / `Keychain`.
- [ ] Implement SSL/TLS certificate pinning via `network_security_config.xml` (Android) or `TrustKit` (iOS).
- [ ] Set `android:exported="false"` on all Android components unless explicitly intended for inter-app communication.
- [ ] Protect sensitive screens against background snapshots using `FLAG_SECURE` (Android) and privacy overlay views (iOS).
- [ ] Disable `allowFileAccess` and audit all `addJavascriptInterface` bindings in WebViews.
- [ ] Transition from custom URL schemes (`myapp://`) to cryptographically verified App Links / Universal Links.
- [ ] Enforce code shrinking, obfuscation, and optimization using ProGuard / R8 in release configurations.
