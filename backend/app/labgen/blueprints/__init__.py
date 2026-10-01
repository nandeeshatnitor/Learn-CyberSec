from app.labgen.blueprints.base import Blueprint, Probe, Rendered, ValidationPlan
from app.labgen.blueprints.expression_injection import ExpressionInjection
from app.labgen.blueprints.path_traversal import PathTraversal

BLUEPRINTS: tuple[Blueprint, ...] = (ExpressionInjection(), PathTraversal())


def get_blueprint(blueprint_id: str) -> Blueprint | None:
    return next((b for b in BLUEPRINTS if b.id == blueprint_id), None)


__all__ = ["BLUEPRINTS", "Blueprint", "Probe", "Rendered", "ValidationPlan", "get_blueprint"]
