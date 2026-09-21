import json
import backend.agents.checks
from backend.core.check_registry import registry
from backend.services.verification_engine import VerificationRegistry

checks = [c for c in registry.get_all_checks() if not c.contract.id.startswith('C999')]
print(f"Total canonical checks: {len(checks)}")

strategy_counts = {}
for c in checks:
    s = c.contract.verification_strategy
    strategy_counts[s] = strategy_counts.get(s, 0) + 1

print("\n--- Breakdown by Check Contract Verification Strategy ---")
for s, count in sorted(strategy_counts.items(), key=lambda x: -x[1]):
    print(f"  {s}: {count}")

print(f"\nTotal generic_reproducibility: {strategy_counts.get('generic_reproducibility', 0)}")
print(f"Total dedicated/specialized: {len(checks) - strategy_counts.get('generic_reproducibility', 0)}")

reg_strats = list(VerificationRegistry._strategies.keys())
print(f"\n--- Registered Strategies in VerificationRegistry ({len(reg_strats)}) ---")
for rs in reg_strats:
    print(f"  {rs}")
