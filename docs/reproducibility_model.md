# AihaX — Deterministic Reproducibility Model

## Deterministic Repeatability
The `ReproducibilityEvaluator` calculates reproducibility confidence using:
1. **Response Invariant Consistency**:
   - Status code stability across multiple probes.
   - Body hash comparison and content length variance (<5% variance allowed for dynamic timestamps).
2. **Differential Comparison**:
   - Baseline response vs Probe response.
   - Requires demonstrably distinct behavior (e.g. status transition or distinct body payload reflection).
   - Inverted control probe checks reversibility.
3. **Dual-Identity Access Differential (IDOR/BOLA)**:
   - Account A owns Resource X.
   - Account B probes Resource X with distinct, uncontaminated session credentials.
   - If Account B receives 401/403 -> Access control enforced (`is_reproduced = False`).
   - If Account B receives 200 with Resource X content -> Confirmed IDOR (`is_reproduced = True`, score >= 0.9).
