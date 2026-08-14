"""
core/remediation — Módulo de remediación de procesos maliciosos.

Re-exporta RemediationEngine para acceso simplificado:
    from core.remediation import RemediationEngine
"""
from core.remediation.engine import RemediationEngine, TerminationResult

__all__ = ["RemediationEngine", "TerminationResult"]
