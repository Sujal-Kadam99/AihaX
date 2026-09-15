# AihaX — Finding Deduplication & Evidence Merging

## Stable Location-Based Fingerprinting

Finding deduplication in AihaX prevents redundant reporting when multiple test payloads identify the same underlying vulnerability.

---

## 1. Fingerprint Formula

Finding fingerprints are generated from structural security properties rather than transient payloads or timestamps:

```python
fingerprint = SHA256(
    check_id + "|" + normalized_endpoint + "|" + normalized_param_location + "|" + vulnerability_category
)
```

### Key Behaviors:
- **Payload Independence**: Multiple SQLi or XSS payloads targeting `id` on `/search` map to the same fingerprint.
- **Subdomain Boundary Preservation**: `example.com` and `api.example.com` produce distinct fingerprints.
- **Normalization Invariance**: Trailing slashes and parameter ordering differences are resolved before hashing.

---

## 2. Evidence Merging Strategy

When duplicate candidate findings are detected:
1. **Primary Selection**: The finding with the highest confidence score or `VERIFIED` status is chosen as primary.
2. **Payload Aggregation**: Unique payloads from secondary findings are appended to `combined_payloads`.
3. **Traceability Preservation**: `evidence_ids` and `request_ids` across all duplicate runs are aggregated for auditing.
