"""The one place this codebase talks to a vendor, and the one place it fails.

Every outbound and inbound integration goes through `execute`. It has two
paths and they are the same path:

* **Recorded.** No credentials, or mode forced to mock. The recorded response
  under `fixtures/integrations/` is returned with `mode="mock"`. This is the
  default and it is what runs on stage, so it is a feature rather than a
  stub: the recorded envelope has the shape the real tool returns, and every
  caller above this line parses it the same way in both modes.
* **Live.** Credentials present. The same arguments go to Composio, with the
  toolkit version pinned so the response shape is the one this code parses.

Three rules hold in both paths:

1. **Nothing raises.** Every exception, including an import failure for a
   package that is not installed, becomes a `VendorResult` with
   `state="error"`. A vendor outage must never reach a request handler and
   must never change the case file, the detector, the incidents or the
   metrics.
2. **Nothing blocks.** A live call runs on a worker thread with a deadline.
   A hung vendor returns a timeout result rather than holding a connection
   open, and no critical path calls into here at all.
3. **Only allowlisted slugs.** `config.ALLOWED_SLUGS` is the whole surface.
   A tool nobody reviewed cannot be reached from application code.

Adapter shape and the execute call: docs/technical-spec/04-COMPOSIO.md
section 4.
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from minny.integrations import config

logger = logging.getLogger("minny.integrations")

FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "integrations"

# A vendor gets this long and not a moment more. The demo does not wait.
LIVE_TIMEOUT_SECONDS = 8.0

# One shared pool so a slow vendor cannot spawn threads without limit.
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="minny-vendor")


@dataclass
class VendorResult:
    """What came back, and how much of it to believe.

    `state` is one of connected, mock or error, matching the capability
    states the UI renders. `ok` says whether the operation did what it was
    asked to do; a mock result is `ok` because the recorded response is a
    success, and it is still clearly labelled `mock` everywhere it surfaces.
    """

    capability: str
    tool_slug: str
    state: str
    ok: bool
    data: Any = None
    error_code: str | None = None
    message: str | None = None
    latency_ms: int = 0
    attempted_live: bool = False
    detail: dict = field(default_factory=dict)

    @property
    def mocked(self) -> bool:
        return self.state == config.MOCK

    def to_json(self) -> dict:
        return {
            "capability": self.capability,
            "tool_slug": self.tool_slug,
            "state": self.state,
            "ok": self.ok,
            "error_code": self.error_code,
            "message": self.message,
            "latency_ms": self.latency_ms,
            "attempted_live": self.attempted_live,
            **({"detail": self.detail} if self.detail else {}),
        }


class FixtureMissing(Exception):
    """A recorded response this build was supposed to ship with."""


def load_fixture(name: str) -> Any:
    path = FIXTURE_DIR / name
    if not path.exists():
        raise FixtureMissing(
            f"{path} is missing. Recorded vendor responses ship with the repo; "
            f"mock mode is the default demo path and cannot run without them."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def execute(
    cap: config.Capability,
    arguments: dict,
    *,
    fixture: str,
    timeout: float = LIVE_TIMEOUT_SECONDS,
) -> VendorResult:
    """Run one allowlisted tool, or return the recorded response instead.

    Never raises. The worst case is a `VendorResult` saying what broke.
    """
    started = time.monotonic()

    if cap.tool_slug not in config.ALLOWED_SLUGS:
        # Unreachable from shipped code. It exists so that it stays that way.
        return VendorResult(
            capability=cap.id,
            tool_slug=cap.tool_slug,
            state=config.ERROR,
            ok=False,
            error_code="tool_not_allowlisted",
            message=f"{cap.tool_slug} is not in the adapter allowlist.",
        )

    if not config.should_attempt_live(cap):
        return _recorded(cap, fixture, started, attempted_live=False)

    try:
        future = _pool.submit(_live_call, cap, arguments)
        payload = future.result(timeout=timeout)
    except FutureTimeout:
        return VendorResult(
            capability=cap.id,
            tool_slug=cap.tool_slug,
            state=config.ERROR,
            ok=False,
            error_code="vendor_timeout",
            message=f"{cap.toolkit} did not answer within {timeout:.0f}s.",
            latency_ms=_ms(started),
            attempted_live=True,
        )
    except ImportError:
        # The package is optional on purpose. `pip install composio` turns the
        # live path on; without it the recorded path is still fully working.
        return _recorded(
            cap,
            fixture,
            started,
            attempted_live=True,
            note="the composio package is not installed",
        )
    except Exception as exc:  # noqa: BLE001 - a vendor must never propagate
        logger.warning("%s failed: %s", cap.tool_slug, exc)
        return VendorResult(
            capability=cap.id,
            tool_slug=cap.tool_slug,
            state=config.ERROR,
            ok=False,
            error_code="vendor_error",
            message=f"{cap.toolkit} call failed: {exc}",
            latency_ms=_ms(started),
            attempted_live=True,
        )

    return _parse_envelope(cap, payload, started)


def _live_call(cap: config.Capability, arguments: dict) -> Any:
    """The real Composio execution. Imported lazily so mock mode needs nothing."""
    from composio import Composio  # noqa: PLC0415 - optional dependency

    client = Composio(
        api_key=config.api_key(),
        toolkit_versions=config.TOOLKIT_VERSIONS,
    )
    return client.tools.execute(
        cap.tool_slug,
        user_id=config.composio_user_id(),
        connected_account_id=config.connected_account(cap),
        arguments=arguments,
    )


def _parse_envelope(cap: config.Capability, payload: Any, started: float) -> VendorResult:
    """HTTP success is not provider success. Read both layers.

    04-COMPOSIO.md section 4: inspect the Composio execution envelope and the
    underlying provider result, then parse into a small application type.
    """
    envelope = payload if isinstance(payload, dict) else {"data": payload}
    successful = envelope.get("successful", envelope.get("successfull"))
    data = envelope.get("data", envelope)

    if successful is False:
        return VendorResult(
            capability=cap.id,
            tool_slug=cap.tool_slug,
            state=config.ERROR,
            ok=False,
            data=data,
            error_code="provider_rejected",
            message=str(envelope.get("error") or "the provider rejected the call"),
            latency_ms=_ms(started),
            attempted_live=True,
        )

    # Slack answers 200 with ok:false and an error string. Same idea, one
    # layer down, and it is the layer that decides whether a message exists.
    if isinstance(data, dict) and data.get("ok") is False:
        return VendorResult(
            capability=cap.id,
            tool_slug=cap.tool_slug,
            state=config.ERROR,
            ok=False,
            data=data,
            error_code=str(data.get("error") or "provider_rejected"),
            message=str(data.get("error") or "the provider rejected the call"),
            latency_ms=_ms(started),
            attempted_live=True,
        )

    return VendorResult(
        capability=cap.id,
        tool_slug=cap.tool_slug,
        state=config.CONNECTED,
        ok=True,
        data=data,
        latency_ms=_ms(started),
        attempted_live=True,
    )


def _recorded(
    cap: config.Capability,
    fixture: str,
    started: float,
    *,
    attempted_live: bool,
    note: str | None = None,
) -> VendorResult:
    try:
        recorded = load_fixture(fixture)
    except Exception as exc:  # noqa: BLE001 - even the fallback fails soft
        return VendorResult(
            capability=cap.id,
            tool_slug=cap.tool_slug,
            state=config.ERROR,
            ok=False,
            error_code="fixture_missing",
            message=str(exc),
            latency_ms=_ms(started),
            attempted_live=attempted_live,
        )

    reason = note or ", ".join(config.missing_for(cap)) or "mock mode is forced"
    return VendorResult(
        capability=cap.id,
        tool_slug=cap.tool_slug,
        state=config.MOCK,
        ok=True,
        data=recorded.get("data", recorded) if isinstance(recorded, dict) else recorded,
        message=f"recorded response, no live call ({reason})",
        latency_ms=_ms(started),
        attempted_live=attempted_live,
        detail={"fixture": fixture},
    )


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
