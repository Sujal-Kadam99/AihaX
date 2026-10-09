"""Legacy direct DVWA runner disabled pending safety-gate completion.

The old runner monkey-patched scope and destination validators and sent requests
outside the campaign RequestEngine. Replace it with a gated campaign benchmark
runner only after Gate A and Gate B pass.
"""

if __name__ == "__main__":
    raise SystemExit(
        "DVWA benchmark blocked: legacy runner bypassed scope and destination "
        "validation. Do not run until Gate A and Gate B pass and a gated runner is available."
    )
