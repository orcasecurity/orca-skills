#!/usr/bin/env python3
"""
Registry mapping a finding type to the pipeline that knows how to fix it.

Adding a specialist is adding an entry here. Types with no entry get the generic
pipeline, which behaves exactly as the orchestrator did before this package
existed — the per-type timeouts and diff budgets are still the ones in
`orchestrator.TIMEOUTS` and `validator._DIFF_LIMITS`, read from those tables
rather than copied, so there is one place to change them.
"""
from config import load_config
from validator import _DIFF_LIMITS

from pipelines.base import FixPipeline, FixPlan
from pipelines.cve import CvePipeline, build_fetcher

# Kept in step with orchestrator.TIMEOUTS. Duplicating the numbers here would
# make them drift, so the orchestrator passes its own table in at call time and
# these are only the fallback for direct callers (tests, tooling).
_DEFAULT_TIMEOUTS = {"sast": 180, "iac": 120, "secret": 120, "cve": 240}

_SPECIALISTS = {
    "cve": CvePipeline,
}


def get_pipeline(feature_type: str, timeouts: dict | None = None,
                 **kwargs) -> FixPipeline:
    """The pipeline for a finding type. Never returns None.

    An unknown type gets the generic pipeline rather than an error: routing is
    decided upstream by `is_fixable`, and a type that got this far should be
    fixed the old way, not dropped here.
    """
    ft = (feature_type or "").lower()
    table = timeouts or _DEFAULT_TIMEOUTS
    timeout = table.get(ft, 180)
    diff_limit = _DIFF_LIMITS.get(ft, 50)

    specialist = _SPECIALISTS.get(ft)
    if specialist is not None:
        # Build the fetcher from config unless the caller injected one (tests do).
        if ft == "cve" and "fetcher" not in kwargs:
            fetcher = build_fetcher(load_config().version_data)
            if fetcher is None:
                # version_data.enabled = false. Hand back the generic pipeline so
                # the switch is an exact revert to the pre-specialist behaviour,
                # rather than a CVE pipeline that cannot resolve anything.
                return FixPipeline(feature_type=ft, timeout_sec=timeout,
                                   diff_limit=diff_limit)
            kwargs["fetcher"] = fetcher
        return specialist(timeout_sec=timeout, diff_limit=diff_limit, **kwargs)
    return FixPipeline(feature_type=ft or "generic", timeout_sec=timeout,
                       diff_limit=diff_limit)


__all__ = ["CvePipeline", "FixPipeline", "FixPlan", "get_pipeline"]
