"""
core/explain/__init__.py — Modulo de explicabilidad XAI de ShadowNet Defender.

Exporta ShapExplainer para uso directo desde otros modulos.
"""
from core.explain.shap_explainer import ShapExplainer

__all__ = ["ShapExplainer"]
