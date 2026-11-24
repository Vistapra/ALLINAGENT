# Framework Compatibility Guide — PHP / Laravel & Multi-Stack Projects

> **Provenance Note:** First-party ALLINAGENT compatibility reference for `@backend` (`Backend Developer`), ensuring stack-aware engineering across polyglot repositories.

1. **Detect Actual Project Stack Before Selecting Tooling:**
   - Inspect `composer.json` + `artisan` + optional `Modules/` (`nwidart/laravel-modules`) for **PHP / Laravel** repositories.
   - Inspect `package.json` + `tsconfig.json` for **Node.js / TypeScript** repositories.
   - Inspect `pyproject.toml` / `requirements.txt` for **Python** repositories.
   - Inspect `go.mod` or `Cargo.toml` for **Go / Rust** repositories.
2. **Never Force Node/Express Scaffolders onto PHP/Laravel Codebases:**
   - Supporting helper `senior-backend/scripts/api_scaffolder.py` targets Express/Fastify/Node patterns. **Never** run Node/Express scaffolders on a Laravel/PHP codebase.
   - On Laravel projects, apply `senior-backend` and `api-design-reviewer` **architectural principles** (REST resource naming, `FormRequest` input validation, Sanctum/Passport/JWT auth middleware, Eloquent eager-loading to prevent N+1 queries, non-breaking API versioning, standardized error envelopes, and idempotent migrations) using native PHP/Laravel conventions (`routes/api.php`, `Modules/*/Routes/api.php`, `FormRequest`, `JsonResource`, `PHPUnit`/`Pest`).
3. **Production & Credential Safety:**
   - **Never** read `.env`, `.env.*`, or credential store files.
   - **Never** run `database_migration_tool.py` or `php artisan migrate` against production databases without explicit Owner approval.
   - **Never** run `api_load_tester.py` against live production endpoints.
