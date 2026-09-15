"""AihaX Phase 5 Real-Target Execution & Attack-Surface Coverage Package."""

from backend.execution.baseline import BaselineCaptureEngine, BaselineSnapshot
from backend.execution.canary import CanaryCategory, CanaryGenerator, CanaryRecord
from backend.execution.differential import (
    ReflectionContext,
    ResponseDifferential,
    ResponseDifferentialEngine,
)
from backend.execution.execution_context import (
    ExecutionContext,
    ExecutionPhase,
    PrerequisiteStatus,
)
from backend.execution.execution_graph import ExecutionGraph, ExecutionGraphNode
from backend.execution.mutation_engine import (
    MutationStrategy,
    ParameterMutation,
    ParameterMutationEngine,
)
from backend.execution.parameter_discovery import ParameterDiscoveryEngine
from backend.execution.parameter_model import (
    DiscoveredParameter,
    ParameterLocation,
    ParameterSource,
    ParameterType,
)

__all__ = [
    "ParameterLocation",
    "ParameterType",
    "ParameterSource",
    "DiscoveredParameter",
    "ParameterDiscoveryEngine",
    "BaselineSnapshot",
    "BaselineCaptureEngine",
    "CanaryCategory",
    "CanaryRecord",
    "CanaryGenerator",
    "MutationStrategy",
    "ParameterMutation",
    "ParameterMutationEngine",
    "ReflectionContext",
    "ResponseDifferential",
    "ResponseDifferentialEngine",
    "ExecutionPhase",
    "PrerequisiteStatus",
    "ExecutionContext",
    "ExecutionGraphNode",
    "ExecutionGraph",
]
