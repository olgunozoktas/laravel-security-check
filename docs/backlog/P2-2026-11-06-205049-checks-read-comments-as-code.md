# Checks read comments as code: a comment that quotes code raises a finding

Created: 2026-11-06 (UTC)
Priority: **P2**
GitHub Issue: _not filed yet_
Tags: false-finding, checks
Size: S
Status legend: `- [ ]` = to do, `- [x]` = implemented

## Context

- Seen in DataVisitors on 2026-11-06, the first run of v0.1.1 on that app: four of its findings were inside comments.
- The shapes: a PHP comment that quotes `->update($request->all())` raises `mass-assignment`; a PHP comment that quotes
  `env('SOME_KEY')` raises `env-outside-config`; a Blade comment (`{{-- … --}}`) that quotes a raw-output tag raises
  `unescaped-blade`.
- The app reworded its comments to get past them. A check that cannot be silenced except by rewording a comment teaches
  people to stop writing comments that name the risk, which is the opposite of the goal.

## Items

- [ ] Strip PHP comments (`//`, `#`, `/* … */`, PHPDoc) before the code checks read a file, with the PHP tokenizer
      (`T_COMMENT`, `T_DOC_COMMENT`), and keep the line numbers.
- [ ] Strip Blade comments (`{{-- … --}}`) before the Blade checks read a view, and keep the line numbers.
- [ ] Tests: each shape above inside a comment is silent; the same code outside a comment is still found.

## Acceptance

- The three shapes raise no finding inside a comment, and still raise one in code.

## Tradeoffs & risks

- Code in a comment is never run, so skipping it loses no real finding.

## How to work on this

- Every change to this package gets its tests, written and run (`vendor/bin/pest`); run the changed package on one
  Laravel app before the tag (`bin/security-check <app folder>`).
