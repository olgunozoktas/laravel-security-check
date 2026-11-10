# Alpine checks: server-built expressions need a way to be marked, and two shapes are false findings

Created: 2026-11-07 (UTC)
Priority: **P2**
GitHub Issue: _not filed yet_
Tags: false-finding, option, checks
Size: M
Status legend: `- [ ]` = to do, `- [x]` = implemented

## Context

- Found while the findings of v0.1.1 on a Laravel application were worked through.
- **No option for code on purpose.** `blade-in-alpine-expression` flags `x-show="{{ $when }}"`, where the server builds a
  piece of Alpine CODE from constants (a condition, a state object, a property name). `Illuminate\Support\Js::from()`
  would turn that code into a string and break it. `safe_raw_output` covers `{!! !!}` only, so such a line cannot be
  marked, and the check can never exit 0 on an app that does this.
- **False shape 1:** `url-binding` flags `:action="[...]"` on a Blade COMPONENT tag (`<x-…>`). There the colon is a PHP
  prop, not an Alpine binding.
- **False shape 2:** `url-binding` flags `:href="safeUrl(result.url)"`, where the value goes through a sanitizer.

## Items

- [ ] An option (`safe_alpine_expressions`, the same shape as `safe_raw_output`): exact expressions that are code on
      purpose, each with its reason in the config.
- [ ] `url-binding`: skip a `:prop` on an `<x-…>` component tag.
- [ ] `url-binding`: an option for sanitizer functions (`safe_url_functions`, for example `['safeUrl']`).
- [ ] Tests: each shape is silent when marked or on a component tag, and still found otherwise.

## Acceptance

- The three shapes can be marked or are silent, and every other shape is still found.

## How to work on this

- Every change to this package gets its tests, written and run (`vendor/bin/pest`); run the changed package on one
  Laravel app before the tag (`bin/security-check <app folder>`).
