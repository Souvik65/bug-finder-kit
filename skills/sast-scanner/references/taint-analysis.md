# Taint Analysis & Data Flow Reference

## Contents
- How analyzers model flow
- Source / sink / sanitizer catalogue by vulnerability class
- Language-specific blind spots
- Reading a flow trace

## How analyzers model flow

| Technique | What it tracks | Strength | Weakness |
|---|---|---|---|
| Pattern matching (AST) | Syntax shapes | Fast, readable | No real flow; misses renamed variables |
| Intra-procedural taint | Flow within one function | Low noise | Misses flows across calls |
| Inter-procedural taint | Flow across functions/files | Finds real-world bugs | Slower; call-graph imprecision (dynamic dispatch, callbacks) |
| Whole-program dataflow (CodeQL) | Global flow with models of libraries | Best recall, variant analysis | Needs a build/database; heavier |

Precision knobs every analyzer trades off: **flow-sensitivity** (order of statements), **context-sensitivity** (which caller), **field-sensitivity** (`obj.a` tainted but `obj.b` not), **path-sensitivity** (branch conditions). Lower sensitivity => more false positives; higher => slower and more misses on timeouts.

## Catalogue by vulnerability class

### SQL injection (CWE-89)
- Sources: request params, headers, JSON body, path segments
- Sinks: `cursor.execute(str)`, `Model.objects.raw`, `sequelize.query(str)`, `db.query(`...`${x}`...`)`, string-built ORM `extra()`/`whereRaw`
- Sanitizers: parameterized queries / bind variables, ORM query builders, strict allow-list for identifiers (table/column names cannot be parameterized)
- Common FP: constant-only f-strings; common FN: dynamic `ORDER BY` / column names

### Command injection (CWE-78)
- Sinks: `os.system`, `subprocess.*(shell=True)`, `child_process.exec`, backticks, `Runtime.exec` with a single string
- Sanitizers: argument-list form without a shell, `shlex.quote` (shell contexts only), allow-lists
- Note: list-form `subprocess.run([...])` with tainted *program name or option flags* can still be argument injection (CWE-88)

### Cross-site scripting (CWE-79)
- Sinks: `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, template `|safe`/`mark_safe`/`{{{ }}}`, `res.send(userHtml)`
- Sanitizers: context-aware output encoding, auto-escaping templates, DOMPurify (HTML context only)
- Remember context: HTML body vs attribute vs JS string vs URL vs CSS each need different encoding

### Path traversal (CWE-22)
- Sinks: `open`, `fs.readFile`, `send_file`, `File(...)`, archive extraction (zip-slip)
- Sanitizers: resolve to canonical path, then verify it starts with the intended base dir; reject `..` and absolute paths; use `secure_filename` for names only

### SSRF (CWE-918)
- Sinks: `requests.get`, `fetch`, `axios`, `urllib`, `HttpClient`, webhook/URL-preview/import-from-URL features
- Sanitizers: allow-list of hosts, resolve DNS then block private/link-local/metadata ranges, disable redirects or re-validate each hop
- Blind spot: DNS rebinding and redirect chains defeat naive string checks

### Insecure deserialization (CWE-502)
- Sinks: `pickle.loads`, `yaml.load` (non-safe loader), `ObjectInputStream`, `unserialize`, `node-serialize`
- Sanitizers: none that are reliable on untrusted data - switch to a data-only format (JSON) or signed payloads

### Code injection / eval (CWE-94/95)
- Sinks: `eval`, `exec`, `Function(...)`, `vm.runInContext`, template engines rendering user-supplied *templates* (SSTI)

### Open redirect (CWE-601), XXE (CWE-611), LDAP/XPath/NoSQL injection, log injection (CWE-117), weak crypto (CWE-327), hardcoded credentials (CWE-798)
Same source->sink reasoning for injection types. Weak crypto and hardcoded credentials are *not* taint problems - they are pattern/config checks (flag `md5`/`sha1` for passwords, `random` for tokens, ECB mode, static IVs, literal keys).

## Language-specific blind spots

- **Python**: dynamic attribute access (`getattr`), decorators that inject request data, Django `extra`/`RawSQL`, Jinja `Markup`/`|safe`
- **JavaScript/TypeScript**: prototype pollution (`merge`/`extend` of user objects), implicit coercion, `req.query` arrays/objects vs strings, framework-specific sinks in React/Vue/Angular
- **Java**: reflection, dependency-injection wiring, Spring `@RequestParam` flows into JdbcTemplate with concatenation, XML parser defaults
- **Go**: `database/sql` `Query` with `fmt.Sprintf`, `text/template` vs `html/template`, `exec.Command("sh","-c",...)`
- **PHP/Ruby**: dynamic includes, `extract`, string interpolation into `system`/`ActiveRecord.where("...#{x}")`

## Reading a flow trace

A trustworthy finding lets you answer four questions. If you cannot, mark it Needs Context:

1. Is the **source** actually attacker-controllable in this deployment?
2. Does every hop **propagate** the dangerous part of the value (not just a length or boolean derived from it)?
3. Is there a **sanitizer** the tool doesn't know about (custom validator, framework middleware, upstream gateway)?
4. Is the **sink** reachable with a payload that survives the sanitizer for *that sink's* context?
