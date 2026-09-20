"""Turning Sentry on, or installing the thing that stands in for it.

`SENTRY_BACKEND_DSN` is the only switch. With it, `sentry_sdk.init` runs with
tracing on, PII off and all three scrubbing hooks wired. Without it nothing
is initialised, nothing is sent, and no network call is made from this
package at all; the same span and breadcrumb functions keep working and
write their payloads to `data/sentry/` instead.

There is no third state. A call site cannot tell the difference and must not
try, which is why `init` is idempotent, never raises, and falls back to
offline on any failure rather than leaving half an SDK configured.
"""

from __future__ import annotations

import atexit
import os
import threading
from pathlib import Path

from minny.observability import scrub
from minny.observability.recorder import RECORDER

DSN_VAR = "SENTRY_BACKEND_DSN"
DEFAULT_SERVICE = "worker"

_lock = threading.Lock()
_STATE: dict = {
    "initialised": False,
    "mode": "offline",
    "dsn_present": False,
    "environment": "development",
    "release": None,
    "service": DEFAULT_SERVICE,
    "traces_sample_rate": 1.0,
    "error": None,
    "sdk": None,
    "autoflush": False,
}


def _env(name: str) -> str | None:
    value = os.environ.get(name)
    return value.strip() or None if value else None


def _release() -> str:
    """The commit this is running, read off the git directory.

    Shelling out to git from an import path is a process spawn on every
    start, so the ref is read directly. A worktree's `.git` is a file
    pointing elsewhere, which is exactly how this repository is developed,
    so that case is handled rather than left to return "unknown".
    """
    override = _env("MINNY_RELEASE")
    if override:
        return override
    try:
        root = Path(__file__).resolve().parent.parent.parent
        git = root / ".git"
        if git.is_file():
            pointer = git.read_text(encoding="utf-8").strip()
            if pointer.startswith("gitdir:"):
                git = Path(pointer.split(":", 1)[1].strip())
                if not git.is_absolute():
                    git = (root / git).resolve()
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref:"):
            ref = head.split(":", 1)[1].strip()
            common = git
            if (git / "commondir").is_file():
                common = (
                    git / (git / "commondir").read_text(encoding="utf-8").strip()
                ).resolve()
            return (common / ref).read_text(encoding="utf-8").strip()[:40]
        return head[:40]
    except OSError:
        return "unknown"


def state() -> dict:
    """Read by every span. Initialises on first use so nothing has to
    remember to call `init` before instrumenting."""
    if not _STATE["initialised"]:
        init()
    return _STATE


def init(
    *,
    dsn: str | None = None,
    environment: str | None = None,
    release: str | None = None,
    service: str | None = None,
    force_offline: bool = False,
    autoflush: bool | None = None,
) -> dict:
    """Idempotent, and offline unless a DSN says otherwise."""
    with _lock:
        if _STATE["initialised"]:
            return dict(_STATE)

        dsn = dsn or _env(DSN_VAR)
        _STATE["dsn_present"] = bool(dsn)
        _STATE["environment"] = environment or _env("MINNY_ENV") or "development"
        _STATE["release"] = release or _release()
        _STATE["service"] = service or _env("MINNY_SERVICE") or DEFAULT_SERVICE
        _STATE["initialised"] = True

        if autoflush is None:
            autoflush = _env("SENTRY_OFFLINE_AUTOFLUSH") not in (None, "0", "false")

        if dsn and not force_offline:
            try:
                import sentry_sdk

                sentry_sdk.init(
                    dsn=dsn,
                    environment=_STATE["environment"],
                    release=_STATE["release"],
                    traces_sample_rate=float(
                        _env("SENTRY_TRACES_SAMPLE_RATE") or 1.0
                    ),
                    send_default_pii=False,
                    # Three hooks, not one: errors, transactions and
                    # breadcrumbs are separate payloads and scrubbing an
                    # error event does not sanitise a span's description.
                    before_send=scrub.before_send,
                    before_send_transaction=scrub.before_send_transaction,
                    before_breadcrumb=scrub.before_breadcrumb,
                )
                sentry_sdk.set_tag("service", _STATE["service"])
                _STATE["mode"] = "sentry"
                _STATE["sdk"] = getattr(sentry_sdk, "VERSION", None)
            except Exception as exc:  # noqa: BLE001 - degrade, never fail
                _STATE["mode"] = "offline"
                _STATE["error"] = f"{type(exc).__name__}: {exc}"
        else:
            _STATE["mode"] = "offline"

        if _STATE["mode"] == "offline" and autoflush:
            _STATE["autoflush"] = True
            atexit.register(_flush_quietly)

        _register_known_identifiers()
        return dict(_STATE)


def _register_known_identifiers() -> None:
    """Teach the scrubber this workspace's account names, if they are there.

    Failing to load the baseline is not an error here. The scrubber's shape
    pattern still covers this dataset, and an observability import must not
    be the reason a command cannot start.
    """
    try:
        from minny.baselines.model import Baselines

        model = Baselines.load()
        names = set(getattr(model, "users", {}) or {})
        owners = getattr(model, "ip_owner", None) or getattr(model, "owners", None)
        if isinstance(owners, dict):
            names.update(str(value) for value in owners.values())
        scrub.register_identifiers(names)
    except Exception:  # noqa: BLE001
        pass


def enabled() -> bool:
    return state()["mode"] == "sentry"


def offline() -> bool:
    return state()["mode"] == "offline"


def reset_for_tests() -> None:
    """Forget the initialisation. Only a test should call this."""
    with _lock:
        _STATE.update(
            {
                "initialised": False,
                "mode": "offline",
                "dsn_present": False,
                "release": None,
                "error": None,
                "sdk": None,
                "autoflush": False,
            }
        )
    RECORDER.reset()


def flush(directory: Path | None = None) -> dict:
    """Write the offline payloads. A no-op with a DSN, where they were sent."""
    current = state()
    if current["mode"] == "sentry":
        try:
            import sentry_sdk

            sentry_sdk.flush(timeout=2.0)
        except Exception:  # noqa: BLE001
            pass
        return {}
    if directory is None:
        # One directory per service. eval, the elastic build and the API are
        # separate processes writing separate runs, and a shared directory
        # would mean whichever finished last was the only one a judge could
        # read.
        directory = _artifact_dir() / current["service"]
    return RECORDER.flush(directory, meta=status())


def _flush_quietly() -> None:
    try:
        if RECORDER.counts()["spans"]:
            flush()
    except Exception:  # noqa: BLE001
        pass


def status() -> dict:
    """What `/observability/status` answers with."""
    current = state()
    counts = RECORDER.counts()
    return {
        "mode": current["mode"],
        "enabled": current["mode"] == "sentry",
        "dsn_present": current["dsn_present"],
        "dsn_variable": DSN_VAR,
        "environment": current["environment"],
        "release": current["release"],
        "service": current["service"],
        "sdk_version": current["sdk"],
        "init_error": current["error"],
        "send_default_pii": False,
        "events_sent_without_dsn": 0,
        "counts": counts,
        "spans": RECORDER.span_stats(),
        "scrubbing": scrub.describe(),
        "offline_artifacts": (
            None
            if current["mode"] == "sentry"
            else str(_artifact_dir() / current["service"])
        ),
    }


def _artifact_dir() -> Path:
    from minny import paths

    return paths.sentry_dir()
