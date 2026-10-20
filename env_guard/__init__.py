"""env-guard: Modern developer CLI for environment file validation, auditing, and generation."""

__version__ = "1.0.0"

from .parser import parse_env, parse_env_entries, expand_variables, EnvEntry
from .validator import SchemaValidator, ValidationError, VariableSchema
from .auditor import SecretAuditor, AuditFinding
from .generator import ExampleGenerator
from .inferrer import SchemaInferrer
from .differ import EnvDiffer, DiffResult

__all__ = [
    "__version__",
    "parse_env",
    "parse_env_entries",
    "expand_variables",
    "EnvEntry",
    "SchemaValidator",
    "ValidationError",
    "VariableSchema",
    "SecretAuditor",
    "AuditFinding",
    "ExampleGenerator",
    "SchemaInferrer",
    "EnvDiffer",
    "DiffResult",
]
