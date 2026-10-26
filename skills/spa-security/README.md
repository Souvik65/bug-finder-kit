# spa-security

> Single Page Application (SPA) and modern frontend framework security audit skill
> for the **bug-finder-kit**. Provides specialized auditing for React, Next.js, Vue,
> Nuxt, Angular, and SvelteKit applications across framework-specific attack surfaces.

---

## What This Skill Covers

| Vulnerability Area | Detection Focus |
|---|---|
| **SSR State Injection** | Unescaped `JSON.stringify` inside `<script>` tags, state breakout |
| **Hydration Attacks** | DOM desync, attribute injection, `suppressHydrationWarning` misuse |
| **Raw Framework Sinks** | `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `{@html}` |
| **Dynamic Component Imports** | User-controlled `import()`, dynamic component tag manipulation |
| **Route Guard Illusions** | Client-only authorization without server API enforcement |
| **Server Components & Actions** | Unauthenticated Next.js Server Actions, RSC data boundary leaks |
| **Template Compilation** | Vue runtime `compile()`, legacy AngularJS sandbox escapes |
| **Build & Dev Artifacts** | Leaked `.map` source maps, exposed dev tools, public `.env` variables |

---

## Scope Boundary

| Skill | What It Covers |
|---|---|
| `xss-detector` | Generic DOM/reflected/stored XSS sinks (`innerHTML`, `eval`) |
| `frontend-secret-scanner` | API keys, tokens, and hardcoded secrets in compiled JS bundles |
| **`spa-security`** | Framework-specific architecture flaws: SSR state breakout, hydration attacks, route guard illusions, Server Actions, and dynamic component imports |

---

## Trigger Phrases

Activate this skill by asking:
- `"SPA security"`, `"SPA security audit"`
- `"React security review"`, `"Next.js security"`
- `"Vue security audit"`, `"Angular security check"`
- `"dangerouslySetInnerHTML audit"`, `"v-html security"`
- `"hydration mismatch vulnerability"`, `"SSR injection"`
- `"client-side route guard bypass"`, `"Server Actions security"`

---

## Directory Structure

```
skills/spa-security/
├── SKILL.md              — Core audit guide (Phases 1–10, all attack classes)
├── README.md             — Overview, scope boundary, and triggers
└── references/
    └── detailed-guide.md — Technical deep-dive on React Server Actions, hydration internals,
                            framework sanitizers, and secure patterns
```
