"""Check the mock fixtures before a freeze.

Everything the UI can click has to resolve, or the parachute has a hole in it.
Run it whenever a fixture changes, and again at the freeze:

    python web/verify_fixtures.py
"""

import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOCK = os.path.join(ROOT, 'fixtures', 'mock')

FILES = [
    'case_file.json', 'incidents.json', 'alerts.json', 'baselines.json',
    'metrics.json', 'blue_proposals.json', 'events.json', 'email_evidence.json',
]

problems = []


def fail(message):
    problems.append(message)


def load(name):
    path = os.path.join(MOCK, name)
    if not os.path.exists(path):
        fail(f'{name}: missing')
        return None
    try:
        with io.open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except ValueError as exc:
        fail(f'{name}: does not parse ({exc})')
        return None


def walk_lines(node, path='case_file'):
    """Yield (where, line) for every evidence_lines entry anywhere in a document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == 'evidence_lines' and isinstance(value, list):
                for line in value:
                    yield f'{path}.{node.get("id") or node.get("incident_id") or key}', line
            elif key in ('lines', 'linked_lines', 'injected_lines') and isinstance(value, list):
                for line in value:
                    yield f'{path}.{key}', line
            else:
                yield from walk_lines(value, f'{path}.{key}')
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from walk_lines(item, f'{path}[{index}]')


def walk_emails(node, path='case_file'):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ('evidence_emails',) and isinstance(value, list):
                for eid in value:
                    yield f'{path}.{key}', eid
            elif key == 'closed_by' and value:
                yield f'{path}.{key}', value
            else:
                yield from walk_emails(value, f'{path}.{key}')
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from walk_emails(item, f'{path}[{index}]')


def main():
    docs = {name: load(name) for name in FILES}
    if problems:
        return report()

    events = {row['line'] for row in docs['events.json']}
    mail_doc = docs['email_evidence.json']
    mail_list = mail_doc if isinstance(mail_doc, list) else mail_doc.get('messages', [])
    mail = {m['evidence_id'] for m in mail_list}
    alert_ids = {a['alert_id'] for a in docs['alerts.json']}

    # 1. Every line number the UI can expand must resolve to raw bytes.
    for name in ('case_file.json', 'incidents.json', 'alerts.json'):
        for where, line in walk_lines(docs[name], name):
            if line not in events:
                fail(f'{where}: line {line} is not in events.json')

    # 2. Every mailbox reference must resolve.
    for name in ('case_file.json', 'incidents.json'):
        for where, eid in walk_emails(docs[name], name):
            if eid not in mail:
                fail(f'{where}: {eid} is not in email_evidence.json')

    # 3. Every alert an incident claims must exist.
    for inc in docs['incidents.json']:
        for aid in inc.get('alerts', []):
            if aid not in alert_ids:
                fail(f'incidents.json {inc["incident_id"]}: alert {aid} is not in alerts.json')

    # 4. The stream must parse, be monotonic, and carry only known frame types.
    stream_path = os.path.join(MOCK, 'stream.ndjson')
    types = {'event', 'alert', 'incident', 'replay_state', 'heartbeat'}
    seq = 0
    frames = 0
    with io.open(stream_path, encoding='utf-8') as handle:
        for number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                frame = json.loads(raw)
            except ValueError as exc:
                fail(f'stream.ndjson:{number}: does not parse ({exc})')
                continue
            frames += 1
            if frame.get('type') not in types:
                fail(f'stream.ndjson:{number}: unknown type {frame.get("type")!r}')
            if frame.get('seq') != seq + 1:
                fail(f'stream.ndjson:{number}: seq {frame.get("seq")} follows {seq}')
            seq = frame.get('seq', seq)
            if frame.get('type') == 'event' and frame['data'].get('line') not in events:
                fail(f'stream.ndjson:{number}: event line {frame["data"].get("line")} is not in events.json')

    # 5. Raw bytes must actually be raw, not a rendering of the parsed fields.
    for row in docs['events.json']:
        if not row.get('raw') or str(row['status']) not in row['raw']:
            fail(f'events.json line {row["line"]}: raw text does not carry its own status')

    print(f'{len(events)} events | {len(alert_ids)} alerts | {len(docs["incidents.json"])} incidents '
          f"| {len(mail)} mailbox records | {frames} stream frames")
    return report()


def report():
    if problems:
        print(f'\n{len(problems)} problem(s):', file=sys.stderr)
        for line in problems:
            print(f'  {line}', file=sys.stderr)
        return 1
    print('fixtures OK')
    return 0


if __name__ == '__main__':
    sys.exit(main())
