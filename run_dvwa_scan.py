"""Legacy DVWA runner disabled pending safety-gate completion.

Use the campaign pipeline after Gate A (enforced, observable egress) and Gate B
(fresh evidence-vault trace) have passed. This legacy script made direct HTTP
requests and reset DVWA state outside that pipeline.
"""

if __name__ == "__main__":
    raise SystemExit(
        "DVWA benchmark blocked: legacy runner bypasses AihaX campaign gates. "
        "Do not run until Gate A and Gate B pass and a gated runner is available."
    )
