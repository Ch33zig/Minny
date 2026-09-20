# Running the UI

```
python web/serve.py
```

Then open **http://localhost:8080/?mock=1**. That is the whole demo, with no backend,
no build step and no install.

## The two modes

| URL | Reads from | Needs a backend |
|---|---|---|
| `http://localhost:8080/?mock=1` | `fixtures/mock/*` | no |
| `http://localhost:8080/` | `/api/*` | yes |

`?mock=1` is the parachute. It is tested last before every freeze and it must keep working.
The mode is visible in the top bar at all times so nobody on stage has to guess which one
is on screen.

For live mode, start the API and point the dev server at it so both come from one origin:

```
uvicorn minny.api.app:app --port 8000
python web/serve.py --api http://127.0.0.1:8000
```

`python -m http.server` from `dist/` will not work: it cannot see `fixtures/`, so the mock
switch dies. `web/serve.py` serves the repository root, maps `/` to `dist/index.html`, and
proxies `/api` (streaming, so SSE on `/api/stream` stays live).

## Keyboard

| Key | Does |
|---|---|
| `1` `2` `3` `4` `5` | Case file, Monitor, Judge, Metrics, Blue agent |
| `e` | Expand or collapse every evidence block in the case file |
| `space` | Play or pause the replay on the monitor |

## Layout

No framework and no build step. `dist/index.html` loads `dist/js/main.js` as an ES module;
everything else is imported from there.

```
dist/index.html        shell, nav, view containers
dist/styles.css        tokens and every view's styling
dist/js/api.js         the one place that knows about ?mock=1
dist/js/evidence.js    line-number to raw-bytes expansion, shared by every view
dist/js/views/*.js     one module per view
```
