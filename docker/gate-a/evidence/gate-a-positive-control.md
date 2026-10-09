# Gate A controlled positive control

**Result:** the local fixture recorded bounded HTTP/HTTPS and DNS activity and denied its external-egress probe. Gate A remains **PARTIAL**.

This harness exercises a local scanner container on an internal-only Docker network. The run's packet captures, DNS/HTTP logs, and container metadata are generated under this directory for local inspection and are intentionally excluded from Git.

The test does **not** complete Gate A: `campaign_worker` does not provision or use this runner, and authorization-scoped external egress allowlisting and redirect-to-out-of-scope tests are not implemented. Keep campaign subprocess tools fail-closed and the DVWA benchmark blocked until those controls exist.
