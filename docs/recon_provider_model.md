# AihaX Reconnaissance Provider Model

## Provider Abstraction

All reconnaissance sources implement `BaseReconProvider` (`backend/recon/providers.py`):

```python
class BaseReconProvider(ABC):
    metadata: ProviderMetadata

    @abstractmethod
    async def discover(
        self,
        target: str,
        context: ReconContext,
        scope_validator: ScopeValidator,
    ) -> ProviderExecutionResult:
        ...
```

## Provider Lifecycle States

```text
DISABLED → MOCK_ONLY / RECORDED_ONLY → LIVE_ADAPTER_READY → LIVE_AUTHORIZED → LIVE_RUNNING → LIVE_COMPLETED / LIVE_FAILED
```

- **`MOCK_ONLY`**: Generates deterministic synthetic records in Audit Mode.
- **`RECORDED_ONLY`**: Emits operation plans in Dry Run Mode without network traffic.
- **`LIVE_ADAPTER_READY`**: Adapter verified and ready for live execution.
- **`LIVE_AUTHORIZED`**: Preflight passed and operator confirmed.
- **`LIVE_COMPLETED`**: Execution succeeded and evidence hashed.
- **`LIVE_FAILED`**: Execution failed with explicit error details.

## Error Handling & Provenance

Providers fail closed. If a CLI tool exits with a nonzero status code or times out:
1. Status is marked `LIVE_FAILED`.
2. Stderr or error category is captured in `error_message`.
3. The failure is recorded in `CanonicalReconSnapshot.errors`.
4. Provider failure is **never** silently converted to zero findings.
