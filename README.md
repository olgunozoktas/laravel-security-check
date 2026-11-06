# laravel-security-check

Security checks for Laravel and Livewire apps, **without AI**: `php artisan security:check` reads the app's config,
routes and source, and changes nothing. Each check is one file. A finding at or above `--fail-on` (default
`medium`) exits 1, so it can gate CI and a pull request.

The rules come from the `laravel-best-practices`, `livewire-security` and `alpinejs-security` skills. The Livewire
and Alpine rules are ports of those skills' calibrated scanners (`bin/scan.php`, `bin/review-security.py`): on one real
app, this package's Alpine checks give the same counts as the skill's reviewer (59 and 7).

## Install

```bash
composer require --dev olgunozoktas/laravel-security-check
php artisan security:check                    # every group
php artisan security:check --only=livewire,alpine --fail-on=high
php artisan security:check --json             # for CI
```

Without installing it, from this repository: `bin/security-check <app folder>` boots the app read-only and runs the same
checks.

## What a finding means

A finding is a **candidate, not a verdict**: a static check sees the shape of the code, not where a value comes from.
Each finding names its file and line, says why the shape is a risk, and gives the exact remedy. Severity:

- **high**: a live hole when the shape is what it looks like (raw SQL from request data, an unguarded Livewire action
  that writes a record, a secret in the code, a back door to log in).
- **medium**: a pattern that becomes a hole when its input is a user's (server data in an Alpine expression, `{!! !!}`).
- **low**: confirm it is intended (a public POST route, `$guarded = []`).
- **info**: a check that could not run (no network for `composer audit`).

A check that throws is reported as a medium finding, "The check failed: …", never as a silent pass. The report says how
many files it read, so "no findings" never hides "read nothing". Files over 1 MB are data and are skipped (counted).

## The checks

| Group | Check | What it finds |
|---|---|---|
| `alpine` | `blade-in-alpine-expression` | Server data inside an Alpine expression attribute (x-data, x-init, @click, :bind …): HTML-escaping does not protect JavaScript (alpinejs-security, seam B). |
| `alpine` | `persisted-secret` | $persist writes plain-text localStorage that any script on the origin reads and that survives logout. |
| `alpine` | `url-binding` | An Alpine-bound href, src or action: a "javascript:" URL in the value runs code on a click (the reviewer's `bind-url-no-scheme-check`). |
| `alpine` | `x-html` | x-html puts its value into innerHTML: an XSS when the value holds anything a user wrote (alpinejs-security, seam A). |
| `code` | `client-file-name` | An upload stored under the name that the browser sent: "../", ".php" and another user's file name are the client's choice. |
| `code` | `csrf-exceptions` | URIs taken out of CSRF protection: another site can send a form there with the user's session. |
| `code` | `env-outside-config` | env() outside config/: after php artisan config:cache it answers null, so a secret check or a feature switch goes quiet. |
| `code` | `forms-without-csrf` | A Blade form that posts with no @csrf: Laravel refuses it (419), or a CSRF exception lets another site post it. |
| `code` | `login-throttle` | A login form with no rate limit: a password can be guessed without end. |
| `code` | `mass-assignment` | A model that accepts every field, or the whole request written into a model: a user can set is_admin, user_id, price. |
| `code` | `raw-sql` | Raw SQL built from a variable: an SQL injection when the variable comes from the request. |
| `code` | `secrets-in-code` | A live secret written into the source, or a .env file in git. |
| `code` | `unescaped-blade` | {!! !!} prints HTML without escaping it: an XSS when any part of it comes from a user. |
| `code` | `unprotected-routes` | A route that changes data (POST, PUT, PATCH, DELETE) with no auth, signed or can middleware: anyone can call it. |
| `code` | `unvalidated-uploads` | A stored upload in a file that never checks the file's type: a user can upload a .php or an .html file. |
| `config` | `app-key` | APP_KEY signs and encrypts cookies, sessions and signed URLs: it must be set and 32 random bytes. |
| `config` | `cors` | CORS that lets every origin read answers, worst with credentials. |
| `config` | `debug-mode` | APP_DEBUG on outside local and testing shows stack traces, config and SQL to every visitor. |
| `config` | `dev-tools-in-production` | Debug tools that show queries, requests and sessions: in `require` they ship to production. |
| `config` | `https-in-production` | In production, APP_URL on http:// makes links, redirects and signed URLs plain HTTP. |
| `config` | `public-files` | Files under public/ that the web server gives to anyone: secrets, a repository, dumps, backups, phpinfo. |
| `config` | `session-cookies` | The session cookie: never readable by scripts, only over HTTPS in production, and not sent by other sites. |
| `dependencies` | `composer-audit` | `composer audit --locked`: the installed packages with a known security advisory. It reads the advisory list over the network once. |
| `livewire` | `computed-cache-without-key` | #[Computed(cache: true)] with no key: the cache key holds no user, so every user reads the first user's value. |
| `livewire` | `identity-public-property` | A public property named for a protected field (email, token, password …) is published and writable by the browser. |
| `livewire` | `middleware-not-repeated` | A Livewire page behind `permission:`, `role:` or `password.confirm`: those do not run again on the update endpoint, so later actions skip the check (livewire-security, rule 5). |
| `livewire` | `model-on-public-property` | A public property typed as a model or a collection publishes its class name and primary key in wire:snapshot. |
| `livewire` | `public-page-props` | A public array bag of page props (props, pageProps, payload, data) publishes the whole bag, often with the logged-in user. |
| `livewire` | `unauthorized-mutator` | A public method that changes a record, with no authorization: every public method is callable from the browser console. |
| `livewire` | `untyped-public-property` | A public property with no type: the browser decides what arrives (an array where the code expects a string). |
| `livewire` | `url-writable-identifier` | A #[Url] property that selects a record, with no #[Locked]: any link sets the record that the component reads. |

## Your own checks

A class in `app/SecurityChecks/` (namespace `App\SecurityChecks`) that implements `Olgun\SecurityCheck\Check` runs
with the others: nothing is registered by hand. A check must not change anything.

## Config

`php artisan vendor:publish --tag=security-check-config`: `public_routes` (URI patterns that are public on purpose)
and `safe_raw_output` (`{!! !!}` contents that are HTML on purpose).
