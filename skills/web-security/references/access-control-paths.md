# Access Control, Insecure Direct Object References, and Path Traversal

## Contents
1. Concepts
2. Code review red flags
3. Testing
4. Fixes
5. Before/after examples

## 1. Concepts

- **Broken access control / insecure direct object reference (IDOR)**: the app takes an identifier from the request (a record id, filename, account number) and returns the object without checking that this user may see it. Automated scanners rarely find this; it needs manual review and requests made as different users.
- **Path traversal**: user-influenced file paths let a request escape the directories the app is meant to use and read (or write) other files on the server. Most common around download, preview, template, and upload features. The app should never touch resources outside its own allowed directories.

## 2. Code review red flags

- Handlers that load an object by id with no check tying it to the current user, role, or tenant
- Authorization enforced only in the UI (hidden buttons) or only on some routes
- Sequential or guessable ids exposed in URLs and treated as the only protection
- File access built from request data: `open(base + user_value)`, `sendFile(req.query.file)`, `include($_GET['page'])`
- Blacklisting of `../` sequences instead of resolving the path and comparing it to an allowed base
- Upload handlers that trust the client-supplied filename, extension, or content type, or store uploads inside the web root with execution enabled

## 3. Testing (authorized)

- Use two accounts of the same role and one of a higher role. As account A, request account B's objects; as a low-privilege user, call admin functions directly.
- Change ids in URLs, bodies, and headers; also try the same action via a different HTTP method.
- For file parameters, check whether the server canonicalizes and restricts the path. A harmless in-scope file or a path error is enough evidence.
- Include direct requests to API endpoints that the UI never calls.

## 4. Fixes

1. **Authorize on the server for every request**: verify the current user may access this specific object and action. This is the real fix.
2. **Use indirect references**: expose random tokens or per-session mappings instead of raw database keys or file names (for example, a random id mapped server-side to the file). This hides keys but does not replace the authorization check.
3. **Resolve and compare paths.** Convert the requested path to an absolute canonical path, then confirm it lies inside the allowed base directory. Equivalents: `realpath` (PHP, C, Python `os.path.realpath`), `getCanonicalPath` (Java), `GetFullPath` (.NET), `Path.resolve` + prefix check (Node).
4. **Prefer allowlists** of permitted files/ids over filtering "bad" characters.
5. **Deny by default**; centralize authorization in middleware or policy code.
6. Run the app with least privilege so a traversal bug can read little.
7. Uploads: generate your own filenames, validate type by content, store outside the web root, never execute uploaded files, set size limits.

## 5. Before/after

Python:
```python
# Vulnerable
return send_file(os.path.join(BASE, request.args["file"]))

# Fixed
base = Path(BASE).resolve()
target = (base / request.args["file"]).resolve()
if not target.is_relative_to(base):
    abort(403)
return send_file(target)
```

IDOR:
```python
# Vulnerable
invoice = Invoice.get(request.args["id"])

# Fixed
invoice = Invoice.get(request.args["id"])
if invoice.owner_id != current_user.id:
    abort(404)
```
