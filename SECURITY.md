# Security Policy

Thank you for taking the time to help improve the security of **CyberShield**.

Security research, responsible disclosure, and clear technical reporting are genuinely appreciated. If you believe you have found a vulnerability, please report it privately and include enough technical detail for reproduction and validation.

---

## Supported Versions

At this stage, security updates are provided for the current development line only.

| Version | Supported |
|--------|-----------|
| main   | ✅ Yes |
| older snapshots / previous revisions | ❌ No |

Because CyberShield is still evolving, fixes may be applied directly to the `main` branch before tagged releases are created.

---

## Reporting a Vulnerability

Please **do not open public GitHub issues** for suspected security vulnerabilities.

Instead, report vulnerabilities privately through one of the following channels:

- **GitHub Security Advisories** via the repository's private reporting feature
- Direct contact with the maintainer, if a private channel is already established

If GitHub private reporting is available for the repository, that is the preferred option.

---

## What to Include in a Report

A good report makes triage much faster. Please include as much of the following as possible:

- affected component or file
- vulnerability type
- clear impact statement
- supported attack scenario
- step-by-step reproduction instructions
- proof of concept, if available
- environment details
- logs, traces, screenshots, or crash output when relevant
- suggested fix, if you already have one in mind

Helpful examples include:

- unauthorized file access
- bypass of interception or protection logic
- memory corruption
- key material exposure
- unsafe cryptographic behavior
- privilege boundary violations
- integrity enforcement bypasses
- logic flaws with real security impact

---

## Response Process

After a valid report is received, the general process is:

1. acknowledge receipt
2. review and reproduce the issue
3. assess impact and affected scope
4. prepare a fix when confirmed
5. publish the fix in the codebase
6. credit the reporter when appropriate

Not every report will result in a security advisory, but every serious report will be reviewed carefully.

---

## Response Time

Best effort targets:

- **Initial acknowledgment:** within **7 days**
- **Triage update:** within **14 days** when reproduction is successful
- **Fix timeline:** depends on complexity, severity, and maintainer availability

Some issues may take longer if they require design changes, deeper verification, or regression testing.

---

## Disclosure Expectations

Please allow reasonable time for investigation and remediation before public disclosure.

Responsible disclosure helps reduce risk for users and improves the quality of the final fix. Once an issue is confirmed and addressed, coordinated disclosure is welcome.

---

## Out of Scope

The following are generally **not treated as security vulnerabilities** unless they produce a clear and realistic security impact:

- style issues
- compiler warnings without security relevance
- theoretical-only concerns without a practical attack path
- missing hardening ideas without an actual exploit path
- reports that depend on unrealistic assumptions only
- denial-of-service claims without a reproducible and meaningful impact case

That said, well-supported research is always welcome, especially when it includes a realistic threat model and technical evidence.

---

## Safe Harbor

Good-faith security research aimed at improving the project is welcome.

Please avoid:

- privacy violations
- data destruction
- service disruption outside what is strictly necessary for proof
- social engineering
- accessing systems or data you do not own or have permission to test

Stay within legal and ethical boundaries while testing.

---

## Credits

Responsible reporters may be acknowledged in release notes, advisories, or project documentation, unless they prefer to remain private.

---

## Maintainer

**Ali Firas (thesmartshadow)**

If you are reporting a serious issue, private reporting is strongly preferred over public discussion.
