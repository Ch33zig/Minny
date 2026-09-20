"""Elasticsearch mapping, ingestion and ES|QL translation.

There is no deployment behind this package and no credential for one, so it
runs offline by default and produces the real artifacts: the strict mapping,
the exact `_bulk` NDJSON, the translated ES|QL per rule and a fidelity report
that compares each translation against the Python rule walker over the whole
event corpus. Set `ELASTICSEARCH_URL` and `ELASTIC_INGEST_API_KEY` and the
same code path talks to a cluster instead.

    python -m minny.elastic.run
"""

from __future__ import annotations

from minny.elastic.client import ElasticClient
from minny.elastic.mapping import alerts_mapping, events_mapping, index_names

__all__ = ["ElasticClient", "alerts_mapping", "events_mapping", "index_names"]
