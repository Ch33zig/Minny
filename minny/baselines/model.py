"""Read side of data/baselines.json.

The signals ask the same four questions about every one of 180,800 events:
has this user used this address, succeeded on this template, been refused it,
or sent this parameter. JSON gives back lists, and a list membership test on
a hot path turns a two-second replay into a two-minute one, so everything is
converted to a set once at load and never scanned again.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from minny import paths


@dataclass(frozen=True)
class UserBaseline:
    user: str
    ips: frozenset
    allowed_paths: frozenset
    denied_paths: frozenset
    denied_counts: dict
    templates_seen: frozenset
    hour_hist: dict
    months_observed: int
    auth_fail: dict


_EMPTY = UserBaseline(
    user="",
    ips=frozenset(),
    allowed_paths=frozenset(),
    denied_paths=frozenset(),
    denied_counts={},
    templates_seen=frozenset(),
    hour_hist={},
    months_observed=0,
    auth_fail={},
)


@dataclass
class Baselines:
    """Indexed view of the fitted baseline."""

    document: dict
    users: dict = field(default_factory=dict)
    ip_owner: dict = field(default_factory=dict)
    template_freq: dict = field(default_factory=dict)
    param_keys: dict = field(default_factory=dict)
    privileged_templates: frozenset = frozenset()
    privileged_prefixes: tuple = ()
    rare_post_success_k: int = 0
    status_freq: dict = field(default_factory=dict)
    rare_status_n: int = 0

    @classmethod
    def from_document(cls, document: dict) -> "Baselines":
        rule = document.get("global", {}).get("privileged_rule", {})
        return cls(
            document=document,
            users={
                name: UserBaseline(
                    user=name,
                    ips=frozenset(entry.get("ips", ())),
                    allowed_paths=frozenset(entry.get("allowed_paths", ())),
                    denied_paths=frozenset(entry.get("denied_paths", ())),
                    denied_counts=entry.get("denied_counts", {}),
                    templates_seen=frozenset(entry.get("templates_seen", ())),
                    hour_hist=entry.get("hour_hist", {}),
                    months_observed=entry.get("months_observed", 0),
                    auth_fail=entry.get("auth_fail", {}),
                )
                for name, entry in document.get("users", {}).items()
            },
            ip_owner=dict(document.get("ip_owner", {})),
            template_freq=dict(document.get("global", {}).get("template_freq", {})),
            param_keys={
                template: frozenset(keys)
                for template, keys in document.get("global", {})
                .get("param_keys", {})
                .items()
            },
            privileged_templates=frozenset(
                document.get("global", {}).get("privileged_templates", ())
            ),
            privileged_prefixes=tuple(rule.get("prefixes", ("/api/admin/",))),
            rare_post_success_k=int(rule.get("rare_post_success_k", 0)),
            status_freq={
                int(code): count
                for code, count in document.get("global", {})
                .get("status_freq", {})
                .items()
            },
            rare_status_n=int(document.get("global", {}).get("rare_status_n", 0)),
        )

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Baselines":
        target = Path(path) if path else paths.baselines_path()
        with open(paths.require(target), "r", encoding="utf-8") as handle:
            return cls.from_document(json.load(handle))

    def user(self, name: str | None) -> UserBaseline:
        """Never raises. An unknown user has an empty baseline, which is what
        makes every signal fire on them rather than crash the replay."""
        if name is None:
            return _EMPTY
        return self.users.get(name, _EMPTY)

    def owner_of(self, ip: str) -> str | None:
        """None means unknown, which is a distinct answer from unowned."""
        return self.ip_owner.get(ip)

    def frequency(self, template: str) -> int:
        return self.template_freq.get(template, 0)

    def known_params(self, template: str) -> frozenset:
        return self.param_keys.get(template, frozenset())

    def status_count(self, status: int) -> int:
        """How often the fitted window produced this status. Zero is a real
        answer: 400 and 500 never occur before March."""
        return self.status_freq.get(int(status), 0)

    def is_privileged(
        self, template: str, method: str | None = None, status: int | None = None
    ) -> bool:
        """Policy prefix first, rarity second.

        The rarity clause is what survives a red-team rename: an attacker who
        moves the escalation endpoint off /api/admin/ still lands on a template
        the baseline has never seen answering 200 to a POST.
        """
        if template in self.privileged_templates:
            return True
        if template.startswith(self.privileged_prefixes):
            return True
        return (
            method == "POST"
            and status == 200
            and self.frequency(template) < self.rare_post_success_k
        )


def load_baselines(path: str | Path | None = None) -> Baselines:
    return Baselines.load(path)
