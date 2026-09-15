# Parameter Mutation & Canary Generation Engine

## 1. Overview

The `ParameterMutationEngine` (`backend/execution/mutation_engine.py`) and `CanaryGenerator` (`backend/execution/canary.py`) generate deterministic, non-destructive mutations for active security checks without executing raw network requests directly.

---

## 2. Canary Generation Matrix

The `CanaryGenerator` creates high-entropy tokens and paired negative controls across vulnerability categories:

| Category | Check IDs | Payload Structure | Negative Control | Expected Signal |
| :--- | :--- | :--- | :--- | :--- |
| **Reflection / XSS** | C037, C039, C059 | `<aihax_refl_{check_id}_{token}>` | `<aihax_ctrl_{token}>` | Unencoded reflection in HTML/DOM context |
| **Arithmetic / SSTI** | C027, C028, C035 | `$(( n1 * n2 ))`, `{{ n1 * n2 }}` | `static_literal` | Calculated integer product ($n_1 \times n_2$) |
| **SQL Syntax Error** | C023, C024 | `'aihax_sql_{token}`, `"aihax_sql_{token}` | Clean baseline input | Database error syntax (e.g., MySQL syntax error) |
| **Boolean Differential**| C023 | `param' AND '1'='1` vs `param' AND '1'='2` | Identical inputs | Differential page structure between TRUE and FALSE |
| **LFI / Traversal** | C031, C032 | `../../../../etc/passwd` | `/valid/path` | Unix `root:.*:0:0:` or `[extensions]` header |
| **File Upload** | C055 | Safe metadata `.txt` / `.png` | `.txt` control | File execution or MIME type bypass confirmation |

---

## 3. Mutation Strategies

1. **`REPLACE`**: Substitutes the target parameter value with the canary payload while preserving all other request parameters.
2. **`APPEND`**: Appends the canary payload to the baseline parameter value (e.g. `param=original<canary>`).
3. **`PREPEND`**: Prepends the canary payload before the baseline value.
4. **`TYPE_CHANGE`**: Changes parameter data type (e.g. converting a scalar integer into an array or JSON object to test type confusion).
5. **`BOUNDARY`**: Inserts maximum integer values, extreme float precision, or boundary-length strings.
6. **`ENCODING`**: Applies URL-encoding, double URL-encoding, Unicode normalization, or Base64 encoding.
7. **`MULTIPART`**: Replaces the multipart filename, content-type header, or file contents in form uploads.

---

## 4. Parameter Mutation Construction Workflow

```python
# Example: Creating a query parameter replacement mutation
spec, mutation = ParameterMutationEngine.create_mutated_request(
    endpoint=endpoint,
    parameter=param,
    canary=canary,
    strategy=MutationStrategy.REPLACE,
)

# Mutated request spec is handed to centralized RequestEngine
evidence = await request_engine.execute(spec)
```
