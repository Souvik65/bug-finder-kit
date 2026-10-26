# mobile-security-review

> Comprehensive iOS and Android mobile application security audit skill for the
> **bug-finder-kit**. Evaluates native (Swift, Kotlin, Java) and cross-platform
> (React Native, Flutter) apps against the OWASP Mobile Application Security Verification
> Standard (MASVS).

---

## What This Skill Covers

| Attack Surface | Audit Focus |
|---|---|
| **Insecure Local Storage** | Plaintext `SharedPreferences`, `UserDefaults`, `AsyncStorage` vs `Keychain` / `EncryptedSharedPreferences` |
| **Transport Security & Pinning** | Certificate pinning, Network Security Config, App Transport Security (ATS) |
| **Deep Link Security** | Insecure custom URL schemes (`myapp://`) vs App Links / Universal Links, parameter tampering |
| **WebView Security** | `addJavascriptInterface` RCE sinks, `setAllowFileAccess`, mixed content |
| **IPC & Android Manifest** | `android:exported="true"`, unprotected activities, services, broadcast receivers |
| **Screen Snapshot Caching** | Mitigating sensitive data exposure in OS app switcher (`FLAG_SECURE`, blur overlays) |
| **Cross-Platform Quirks** | React Native `react-native-keychain`, Flutter `flutter_secure_storage` |
| **Binary Hardening** | ProGuard / R8 obfuscation, root/jailbreak detection guidelines |

---

## Scope Boundary

| Skill | What It Covers |
|---|---|
| `web-app-security` | Web browsers, DOM security, web cookies, CORS, CSP |
| `api-security-review` | Backend server APIs that mobile applications communicate with |
| **`mobile-security-review`** | Client-side mobile binary security: iOS/Android native APIs, OS sandboxing, KeyStore/Keychain, WebViews, and IPC components |

---

## Trigger Phrases

Activate this skill by asking:
- `"mobile security review"`, `"iOS security audit"`
- `"Android security audit"`, `"certificate pinning check"`
- `"WebView security audit"`, `"deep link security"`
- `"exported components review"`, `"insecure local storage"`
- `"Keychain audit"`, `"SharedPreferences security"`
- `"React Native security"`, `"OWASP MASVS"`

---

## Directory Structure

```
skills/mobile-security-review/
├── SKILL.md              — Core audit guide (Phases 1–8, MASVS taxonomy, code examples)
├── README.md             — Overview, scope boundary, and triggers
└── references/
    └── detailed-guide.md — OWASP MASVS checklist, certificate pinning rotation,
                            Frida bypass defenses, and KeyStore/Keychain implementation details
```
