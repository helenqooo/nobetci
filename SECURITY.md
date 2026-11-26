# Security policy

Nöbetçi runs with administrator rights, watches the whole system and can stop processes and quarantine files, so security reports are welcome.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer within 7 days.
Fixes are released as soon as they are ready, and reporters are credited unless they ask not to be.

## In scope

- Detection bypasses that a real sample could use (please include a harmless proof of concept)
- Ways for a non-admin process to make Nöbetçi kill, quarantine or trust something it should not
- Crashes or hangs caused by crafted files during scanning

## Out of scope

- Attacks that already need administrator or kernel access (Nöbetçi has no kernel driver; see the README)
- Denial of service through volume alone
