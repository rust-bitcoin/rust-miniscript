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
6.  `Lint`
7.  `Docs`
8.  `Docsrs`
9.  `Bench`
10. `Format`
10. `Int-tests`
11. `Embedded`
