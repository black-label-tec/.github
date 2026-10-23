# Black Label shared source integrity

The reusable workflow checks committed changes without executing product code,
using secrets, installing a service, changing schedules, or publishing a release.
It runs on pull requests and merge groups when a caller opts in. The caller must
pin the reusable workflow to its reviewed full commit SHA.

It records the tested revision, base, changed blob identities and a manifest
digest. It rejects new recognized credentials, oversized blobs and symlinks that
escape the checkout. It does not replace a dedicated secret scanner, product
tests, integration tests, physical acceptance, or release approval. Receipts
explicitly set `release_authorized: false` and `runtime_acceptance: not_checked`.

## Development

Run `python3 -m unittest discover -s . -p 'test_integrity.py' -v`, then
`python3 generate_workflow.py`. The generated workflow embeds the reviewed
checker so private product code never needs to be sent to a separate service.
Both the source and generated workflow must be committed together.

Repository administrators must separately configure required status checks.
Adding a workflow file does not prove that it is mandatory or that an existing
release workflow waits for it. Product release holds and platform restrictions
remain authoritative.
