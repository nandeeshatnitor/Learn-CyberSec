"""Bump when the pipeline, prompt, guide schema or validator change in a way that makes cached
guides stale: a READY run with a different version is regenerated instead of reused."""

GENERATION_VERSION = "1"
