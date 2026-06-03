# Changelog

All notable changes to `padosoft/laravel-rebel-bridge-fortify` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-06-03

### Changed
- **Richer login audit context.** Framework login/logout events now record the request IP and
  User-Agent (as keyed HMACs, never plaintext), and a successful login records `aal=aal1` plus
  the `pwd` factor in `amr` when a password field is present. Previously only the guard + subject
  were captured, leaving the audit detail's IP / User-Agent / assurance / AMR empty.

## [0.1.0] - 2026-06-03

### Added
- **Step-up drivers** exposing Fortify/framework factors through the Rebel step-up
  `StepUpDriver` contract:
  - `fortify_password_confirm` — password re-confirmation (AAL1, not phishing-resistant).
  - `fortify_totp` — Fortify TOTP two-factor, plus single-use recovery codes consumed
    **atomically** (row lock + targeted update + audit). AAL2, not phishing-resistant.
  - `fortify_passkey_confirm` — passkey/FIDO2 confirmation bound to a **single-use,
    server-issued challenge** (replay-resistant). AAL2, phishing-resistant.
- **Fortify event mapper**: framework auth events (Login/Failed/Logout/Lockout) and
  Fortify two-factor lifecycle events are recorded into the Rebel audit trail. Lockouts
  store the IP and identifier as keyed HMACs (never plaintext PII).
- **Passkey-first login** orchestration (`PasskeyFirstLogin`) with an email-OTP fallback
  signal, challenge-bound assertion verification, and audit (AMR claimed only on success).
- **Contracts + test fakes**: `PasskeyConfirmer`, `PasskeyAuthenticator`,
  `FakePasskeyConfirmer`, `FakePasskeyAuthenticator`.
- **Feature detection**: the bridge installs and works even when Fortify is absent (the
  password-confirm driver keeps working; Fortify-only pieces are skipped).
- Config file, CI matrix (PHP 8.3/8.4/8.5 × Laravel 12/13), Pest suite, PHPStan level max, Pint.

[Unreleased]: https://github.com/padosoft/laravel-rebel-bridge-fortify/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/padosoft/laravel-rebel-bridge-fortify/releases/tag/v0.1.0
