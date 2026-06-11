"""Redaction engine: structural rules (L1), pattern/entropy scrubbing (L2), output shaping (L3).

Everything model-visible flows through this package. Failures anywhere in the
pipeline must fail closed — callers wrap rendering in a guard that returns a
generic error instead of the payload.
"""

from .patterns import RedactionStats, scrub_text
from .render import (
    UNTRUSTED_BEGIN,
    UNTRUSTED_END,
    dedupe_events,
    envelope,
    render_event_lines,
    render_pod_table,
    render_yaml,
    wrap_untrusted,
)
from .structural import sanitize_object

__all__ = [
    "UNTRUSTED_BEGIN",
    "UNTRUSTED_END",
    "RedactionStats",
    "dedupe_events",
    "envelope",
    "render_event_lines",
    "render_pod_table",
    "render_yaml",
    "sanitize_object",
    "scrub_text",
    "wrap_untrusted",
]
