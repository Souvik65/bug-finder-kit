# Injection (SQL, OS command, LDAP, XPath)

## Contents
1. The idea
2. Code review red flags
3. Safe detection
4. Fixes
5. Before/after examples

## 1. The idea

Injection happens when untrusted input is spliced into text that an **interpreter** then executes (a SQL engine, a shell, an LDAP or XPath processor). The attacker's data changes the structure of the command, not just its values. It remains one of the most damaging web flaws and one of the easiest to fix.

Typical impact: reading or changing database contents, bypassing login, and, with OS command injection, running commands as the web app's account.

## 2. Code review red flags

- SQL built with string concatenation or interpolation (`"... WHERE name='" + term + "'"`, f-strings, template literals)
- ORM "raw query" escape hatches fed with request data
- Stored procedures that build dynamic SQL internally (parameter use in a procedure does not make it safe if it concatenates)
- Process or shell calls with request data: `os.system`, `subprocess(..., shell=True)`, `exec`, `Runtime.exec` with a single string, backticks, `child_process.exec`
- LDAP filters or XPath expressions assembled from input
- Input validated only on the client side
- Database account used by the app has admin-level rights, or dangerous features (like OS command execution from SQL) are enabled
- Sensitive columns (passwords, card numbers) stored in plaintext

## 3. Safe detection (authorized targets only)

- Send a lone quote character in a parameter. A database error or changed behavior suggests the query structure is affected.
- Send a matched pair of logically true and false conditions. Different responses suggest the input is being interpreted.
- Observe error messages: verbose database errors are a separate finding (information leakage).
- For command injection, look for parameters that feed system utilities (ping, lookup, file conversion tools) and review the code path rather than sending destructive commands.

Stop once you have shown that input influences the interpreter. Do not dump tables, add accounts, or run system commands to "prove" it.

## 4. Fixes (in priority order)

1. **Parameterized queries / prepared statements.** Placeholders keep the SQL structure fixed and send input as data. This is the primary fix.
2. **Allowlist validation**: accept only known-good values (a dropdown of state codes, an enum, a numeric ID). Validate on the server even if the UI restricts choices, since a proxy can alter requests. Canonicalize input (reduce to simplest form) before validating.
3. **Escape/encode** for the target interpreter only as a fallback when parameterization is impossible, using a vetted library, not hand-rolled filters. Blacklists of "bad characters" get bypassed.
4. **Least privilege** for the database account: separate accounts for read vs write where practical; no admin rights for the app.
5. **Disable unneeded database features**, especially anything that can run OS commands.
6. **Avoid the shell.** If you must run an external program, call it through an API that takes the program and an argument list separately (no shell string, no chained commands), and allowlist the arguments.
7. **Encrypt/hash sensitive data** so a successful read isn't a full breach (passwords with a slow, salted hash; see `auth-session.md`).
8. **Generic error messages** to users; log details server-side.

## 5. Before/after

Python, SQL:
```python
# Vulnerable
cur.execute("SELECT * FROM shoes WHERE name = '" + term + "'")

# Fixed
cur.execute("SELECT * FROM shoes WHERE name = %s", (term,))
```

Node, command execution:
```js
// Vulnerable: one string, shell interprets metacharacters
exec("ping -c 1 " + host);

// Fixed: no shell, argument list, validated input
if (!/^[a-zA-Z0-9.-]{1,253}$/.test(host)) throw new Error("invalid host");
execFile("ping", ["-c", "1", host]);
```
