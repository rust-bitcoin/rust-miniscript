# rust-miniscript workflow notes

We are attempting to run max 20 parallel jobs using GitHub actions (usage limit for free tier).

ref: https://docs.github.com/en/actions/learn-github-actions/usage-limits-billing-and-administration

The minimal/recent lock files are handled by CI (`rust.yml`).

## Jobs

Run from `rust.yml` unless stated otherwise. Total 11 jobs.

1.  `Stable - minimal`
2.  `Stable - recent`
3.  `Nightly - minimal`
4.  `Nightly - recent`
5.  `MSRV - minimal`
6.  `MSRV - recent`
7.  `Lint`
8.  `Docs`
9.  `Docsrs`
10. `Bench`
11. `Format`
12. `Int-tests`
13. `Embedded`
