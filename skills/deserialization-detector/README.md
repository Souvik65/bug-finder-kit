# deserialization-detector

> Insecure deserialization and gadget-chain detection skill for the **bug-finder-kit**.
> Addresses OWASP Top 10 A08 (Software and Data Integrity Failures) by auditing
> Java, Python, PHP, .NET, Ruby, and Node.js codebases for dangerous object reconstruction sinks.

---

## What This Skill Covers

| Ecosystem | Vulnerability Targets | Primary Safe Replacement |
|---|---|---|
| **Java** | `ObjectInputStream.readObject()`, Jackson `enableDefaultTyping()`, Fastjson | JEP 290 filter, Protocol Buffers, strict Jackson Polymorphic Validator |
| **Python** | `pickle.loads()`, `_pickle`, `shelve`, `yaml.load()` without `SafeLoader` | `json.loads()`, `yaml.safe_load()`, signed Pydantic models |
| **PHP** | `unserialize()`, POP chains (`__wakeup`, `__destruct`), `phar://` wrappers | `json_decode()`, `allowed_classes` whitelist |
| **.NET** | `BinaryFormatter.Deserialize()`, `TypeNameHandling.All` in Newtonsoft.Json | `System.Text.Json`, `TypeNameHandling.None` |
| **Ruby** | `Marshal.load()`, `Psych.load()` | `JSON.parse()`, `Psych.safe_load()` |
| **Node.js** | `node-serialize.unserialize()`, prototype pollution in custom parsers | Native `JSON.parse()` |

---

## Trigger Phrases

Activate this skill by asking:
- `"insecure deserialization"`, `"deserialization vulnerability"`
- `"audit pickle"`, `"pickle.loads"`
- `"ObjectInputStream review"`, `"Java deserialization"`
- `"PHP unserialize"`, `"phar deserialization"`
- `"Jackson default typing"`, `"BinaryFormatter .NET"`
- `"find gadget chains"`, `"POP chain analysis"`

---

## Directory Structure

```
skills/deserialization-detector/
├── SKILL.md              — Main audit guide (Phases 1–8, code sinks, remediations)
├── README.md             — Overview, triggers, and ecosystem mappings
└── references/
    └── detailed-guide.md — Gadget chain anatomy, JEP 290 filtering, and phar hardening
```

---

## Author & Version
`bug-finder-kit` — v1.0.0 — 2026-10-21
