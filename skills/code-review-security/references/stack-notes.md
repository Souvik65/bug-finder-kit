# Stack-Specific Footguns

Contents: Next.js/React · Node/Express · Python/Django · Supabase/Postgres · MongoDB/MySQL · n8n/webhooks · LLM-integrated code

Read only the section(s) that match. Focus on where code *opts out* of framework protection or where the framework leaves a gap.

## Next.js / React / TypeScript
- `dangerouslySetInnerHTML`, `innerHTML`, unsanitized markdown rendering: XSS. Require DOMPurify or equivalent.
- `NEXT_PUBLIC_*` env vars are shipped to the browser. Any secret there is public.
- Route handlers and server actions are public HTTP endpoints. Each needs its own authn + authz check; middleware matchers often miss routes (check `matcher`, trailing slashes, `/api` vs `/_next/data`).
- Server actions: validate input with a schema; don't trust hidden form fields or bound args for IDs/roles.
- Authorization done only in client components or layouts is not authorization. Enforce in the data-access layer.
- `redirect()` / `router.push` with user-supplied URLs: open redirect. Allowlist.
- `fetch` to user-supplied URLs from server code: SSRF.
- TypeScript types vanish at runtime. `as User` on request JSON validates nothing.
- Cache pitfalls: user-specific data cached or statically rendered and served to others.

## Node / Express
- Missing `helmet`, body-size limits, rate limiting, and CORS allowlist.
- `req.body` passed straight to ORM `create/update`: mass assignment.
- `child_process.exec` with interpolated strings: command injection. Use `execFile` with an args array.
- `jsonwebtoken.verify` without pinned `algorithms`; accepting `none` or HS/RS confusion.
- Prototype pollution via recursive merge / `Object.assign` of untrusted JSON.
- Regex built from user input or catastrophic backtracking (ReDoS).
- `Math.random()` used for tokens, IDs, or reset codes.

## Python / Django
- `DEBUG=True`, wildcard `ALLOWED_HOSTS`, hardcoded `SECRET_KEY`.
- `.raw()`, `.extra()`, `cursor.execute(f"...")`: SQL injection. Use params.
- `mark_safe`, `|safe`, `autoescape off`: XSS.
- `@csrf_exempt` on cookie-authed views. DRF: default permission classes missing (`AllowAny` default); serializers with `fields = "__all__"` exposing sensitive fields or allowing mass assignment.
- Object-level checks: `Model.objects.get(pk=pk)` without filtering by `request.user` (IDOR). Prefer `get_object_or_404(Model, pk=pk, owner=request.user)`.
- `pickle`, `yaml.load` (not `safe_load`), `eval`, `subprocess(..., shell=True)` on untrusted data.
- File uploads: trusting `content_type`/extension; `MEDIA_ROOT` served by the app with executable types.
- Missing `SECURE_*` / cookie flags in production settings (run `manage.py check --deploy`).

## Supabase / Postgres
- Tables in `public` without RLS enabled are readable/writable by anyone with the anon key. Every client-exposed table needs RLS **and** policies.
- Policies using `USING (true)` or checking only `auth.role() = 'authenticated'`: any logged-in user reaches all rows.
- UPDATE/INSERT policies need `WITH CHECK`, not only `USING`, or users can reassign ownership.
- Service-role key in client code, public env vars, or repos: full RLS bypass. Rotate if exposed.
- `SECURITY DEFINER` functions without `set search_path` and without caller checks; views bypass RLS unless `security_invoker`.
- Storage buckets: check whether they are public and what per-path/owner policies exist.
- Realtime/presence channels: confirm authorization on who can subscribe and broadcast (guessable channel names leak cursor/presence data across rooms).
- Use `auth.uid()` in policies; never trust a user-id column supplied by the client.

## MongoDB / MySQL
- Mongo: request JSON passed into queries allows operator injection (`{"password": {"$ne": ""}}`). Cast to expected scalar types; use schema validation; disable `$where`.
- MySQL: prepared statements everywhere; watch dynamic `ORDER BY`/column/table names (allowlist), multi-statement mode enabled.
- DB account used by the app should not be root/admin; separate migration and runtime users.
- Connection strings with credentials in code or logs; DB port exposed publicly.

## n8n / webhooks / automation
- Webhook nodes without auth or signature verification are public triggers.
- Credentials echoed in execution logs/outputs; execution data retention containing PII.
- Expressions interpolating untrusted input into HTTP, code, or shell nodes (injection / SSRF).
- Bot tokens (Telegram, etc.) hardcoded in exported workflow JSON.
- Admin UI exposed without auth or behind a default basic-auth password.

## LLM-integrated code
- Treat model output as untrusted input: never pass it unchecked to `eval`, shell, SQL, or HTML.
- Prompt injection: user or retrieved content can steer tool calls. Gate destructive tools with confirmation and server-side authz, not prompt instructions.
- API keys (OpenAI/Gemini/Anthropic) stay server-side; add per-user rate limits and spend caps.
- Don't log full prompts/responses containing PII or secrets.
- Retrieval over multi-tenant data must filter by tenant before the model sees it.
