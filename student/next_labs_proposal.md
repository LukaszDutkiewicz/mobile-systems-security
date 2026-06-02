# Proposal for next labs

## What the sequence already covers

- L01: threat modeling and attack surface
- L02/L03: secrets, hashes, local storage, and password handling
- L04: MFA with TOTP, rate limiting, replay, and fallback
- L05: biometrics as a local gate to a secret
- L06: face enrollment, camera capture, and on-device model workflow

The overall course arc is moving from secret handling to local trust decisions, and then to stronger trust signals from the platform and application provenance.

## Good idea for the next labs

The next lab should focus on **app provenance, runtime trust, and privacy hardening** on mobile.

This is a good fit because it naturally continues from:

- local secrets and session handling,
- biometrics as a gate to keys,
- face biometrics as a local on-device pipeline,
- the syllabus topics around Android security, signing, configuration, and privacy.

## Suggested exercise set

### 1. Manifest and privacy audit

Students inspect a starter app and:

- map every permission and privacy declaration to a concrete feature,
- remove or justify overbroad declarations,
- identify declarations that are correct but misleading,
- explain which prompts are runtime prompts and which are only manifest/config declarations.

Why this is useful:

- it teaches that a declared capability is not the same thing as a justified capability,
- it connects directly to real mobile risk and review workflows.

### 2. APK / bundle provenance check

Students add a simple verification flow that:

- checks whether the app build identity matches the expected signing identity,
- rejects a tampered or repackaged build,
- distinguishes install-time trust from runtime trust.

Why this is useful:

- it fits the transition from local security to platform trust,
- it makes the idea of "same app" concrete.

### 3. Integrity-gated backend request

Students implement a mock backend gate that accepts requests only when:

- the client presents a valid integrity signal,
- the request is bound to the current app build identity,
- the app falls back safely when trust cannot be established.

Why this is useful:

- it connects client-side security with server-side policy,
- it shows that trust decisions are not purely local.

### 4. Secret hygiene under backup and migration

Students harden the app so that:

- sensitive data is excluded from backup,
- local secrets are re-derived or re-provisioned correctly after migration,
- debug logging and analytics do not leak credentials, tokens, or biometric artifacts.

Why this is useful:

- it closes the gap between "works on one phone" and "safe across device lifecycle".

## Best single lab if you want one compact exercise

If only one exercise should be built, make it:

**"Trust the app, not the package name"**

The student task would be to:

- audit the app manifest and privacy declarations,
- implement a minimal provenance check,
- enforce a safe fallback path when trust checks fail,
- prove the behavior with tests.

That gives a clean bridge from biometric/local-secret labs into platform integrity and Android security.

