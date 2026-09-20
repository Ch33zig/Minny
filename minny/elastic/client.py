"""One client, two modes, and no third code path.

There is no Elastic deployment behind this repository and there are no
credentials for one, so the default mode is offline. Offline is not a stub:
it produces the exact NDJSON body that would be POSTed to `_bulk`, writes it
where it can be read and replayed, and answers ES|QL from a local executor
that models the same null semantics. When `ELASTICSEARCH_URL` and
`ELASTIC_INGEST_API_KEY` are set, the same call sites send the same bytes
over HTTP instead.

Transport is `urllib`. The Bulk and ES|QL APIs are NDJSON and JSON over HTTP
with an `Authorization: ApiKey` header, so a client library would add a
dependency that cannot be exercised here and would put a second serializer
between the offline payload and the live one. The point of this file is that
those two are the same bytes.

Nothing in here raises. Every method returns a result dict with `ok`, and a
failure carries `error` and `error_kind`. An unreachable cluster degrades to
offline and says so; it does not take down a request handler.
"""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request

from minny.elastic.mapping import index_names

DEFAULT_WORKSPACE = "minny-local"
DEFAULT_TIMEOUT_S = 5.0
USER_AGENT = "minny-elastic/1"


def _env(name: str) -> str | None:
    value = os.environ.get(name)
    return value.strip() or None if value else None


def credentials_present() -> bool:
    return bool(_env("ELASTICSEARCH_URL") and _env("ELASTIC_INGEST_API_KEY"))


class ElasticClient:
    """Reads its configuration from the environment, once, at construction."""

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        *,
        workspace_id: str | None = None,
        timeout: float | None = None,
        opener=None,
    ):
        self.url = (url or _env("ELASTICSEARCH_URL") or "").rstrip("/")
        self.api_key = api_key or _env("ELASTIC_INGEST_API_KEY") or ""
        self.workspace_id = (
            workspace_id or _env("MINNY_WORKSPACE_ID") or DEFAULT_WORKSPACE
        )
        self.timeout = float(
            timeout if timeout is not None else _env("ELASTIC_TIMEOUT_S") or DEFAULT_TIMEOUT_S
        )
        self.indices = index_names(self.workspace_id)
        # Injected by the tests so an unreachable cluster can be exercised
        # without waiting on a real socket timeout.
        self._opener = opener or urllib.request.urlopen
        self.last_error: dict | None = None

    # ------------------------------------------------------------ modes

    @property
    def configured(self) -> bool:
        """Both halves of the credential, or neither. A URL with no key is a
        misconfiguration that would fail on the first request; catching it
        here means the run reports offline rather than reporting an error."""
        return bool(self.url and self.api_key)

    @property
    def mode(self) -> str:
        return "online" if self.configured else "offline"

    def describe(self) -> dict:
        return {
            "mode": self.mode,
            "configured": self.configured,
            "url_present": bool(self.url),
            "api_key_present": bool(self.api_key),
            "workspace_id": self.workspace_id,
            "indices": dict(self.indices),
            "timeout_s": self.timeout,
            "last_error": self.last_error,
        }

    # --------------------------------------------------------- transport

    def _request(self, method: str, path: str, body: bytes | None, content_type: str) -> dict:
        if not self.configured:
            return {
                "ok": False,
                "error_kind": "offline",
                "error": "ELASTICSEARCH_URL and ELASTIC_INGEST_API_KEY are not set",
                "status": None,
            }
        request = urllib.request.Request(
            f"{self.url}{path}",
            data=body,
            method=method,
            headers={
                "Authorization": f"ApiKey {self.api_key}",
                "Content-Type": content_type,
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        started = time.perf_counter()
        try:
            with self._opener(request, timeout=self.timeout) as response:
                payload = response.read().decode("utf-8")
                status = response.status
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8")[:500]
            except Exception:  # noqa: BLE001 - the body is a nicety, not a need
                detail = ""
            return self._fail("http_error", f"HTTP {exc.code}: {detail}", exc.code)
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            # No route, DNS failure, TLS refusal, timeout. All the same answer
            # to a caller: the cluster is not there, carry on without it.
            return self._fail("unreachable", str(exc), None)
        except Exception as exc:  # noqa: BLE001 - fail soft is the whole point
            return self._fail("unexpected", f"{type(exc).__name__}: {exc}", None)

        elapsed = time.perf_counter() - started
        try:
            parsed = json.loads(payload) if payload else {}
        except ValueError as exc:
            return self._fail("bad_response", f"response was not JSON: {exc}", status)
        self.last_error = None
        return {"ok": True, "status": status, "body": parsed, "seconds": elapsed}

    def _fail(self, kind: str, message: str, status) -> dict:
        self.last_error = {"kind": kind, "message": message[:500], "status": status}
        return {"ok": False, "error_kind": kind, "error": message[:500], "status": status}

    # ------------------------------------------------------------- calls

    def ping(self) -> dict:
        """`GET /`, which is the only thing that proves credentials work."""
        result = self._request("GET", "/", None, "application/json")
        if not result.get("ok"):
            return result
        body = result.get("body") or {}
        version = (body.get("version") or {}).get("number")
        return {
            "ok": True,
            "cluster_name": body.get("cluster_name"),
            "version": version,
            "seconds": result.get("seconds"),
        }

    def create_index(self, name: str, mapping: dict) -> dict:
        body = json.dumps(mapping).encode("utf-8")
        result = self._request("PUT", f"/{name}", body, "application/json")
        if not result.get("ok") and result.get("status") == 400:
            # resource_already_exists_exception is the normal second run.
            return {"ok": True, "created": False, "name": name}
        if not result.get("ok"):
            return result
        return {"ok": True, "created": True, "name": name}

    def bulk(self, ndjson: str, *, refresh: str | None = None) -> dict:
        """POST one NDJSON batch. The body must end in a newline."""
        path = "/_bulk"
        if refresh:
            path = f"{path}?refresh={refresh}"
        return self._request(
            "POST", path, ndjson.encode("utf-8"), "application/x-ndjson"
        )

    def count(self, index: str) -> dict:
        return self._request("GET", f"/{index}/_count", None, "application/json")

    def esql(self, query: str, *, filter_dsl: dict | None = None) -> dict:
        """POST /_query with partial results refused.

        A partial result is an error, never a smaller answer. Reporting
        "0 matches" from a query that half ran is the one failure mode that
        would make a detection claim untrue.
        """
        payload: dict = {"query": query}
        if filter_dsl:
            payload["filter"] = filter_dsl
        body = json.dumps(payload).encode("utf-8")
        return self._request(
            "POST",
            "/_query?format=json&allow_partial_results=false",
            body,
            "application/json",
        )
