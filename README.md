# mini-SOAR (Go port)

A 1:1 port of the Python mini-SOAR PoC to Go — engine **and** Thai web UI.

## What's here

| File / dir | Ported from |
|---|---|
| `core.go` | `app/core.py` (engine: extraction, matching, actions, playbooks, approvals) |
| `main.go` | `app/main.py` (webhook + Thai UI + 19 admin-API routes) |
| `templates/*.html` | `app/templates/*.html` (rewritten from Jinja2 to Go `html/template`) |
| `static/style.css` | unchanged |
| `playbooks/*.yaml` | data (the single source of truth) |
| `config.yaml` | unchanged |

## Run

```bash
go build -o minisoar-go .
./minisoar-go          # http://localhost:8080
```

## Parity with the Python version

Identical behaviour, verified live:

- `POST /webhook` — SIEM-agnostic intake (Wazuh / Elastic / Splunk / Sentinel schemas)
- Playbook matching: `pattern` regex + `keywords`, `min_severity` floor, `not_ip` whitelist,
  `rule_id` / `rule_group` in the haystack
- Actions: `notify` (LINE Messaging API / simulated), `block_ip` (stateful, backend-configurable),
  `isolate_host`, `preserve_evidence`, `audit`
- Human gates with per-step `gate` override, the **locked** `isolate_host` safety envelope,
  and the approval **time-box** (`auto_execute` / `escalate`)
- Thai web UI: dashboard / playbooks / approvals / audit, live-refresh JS, edit modal,
  keyword chips, ordered step list, dry-run preview, undo (revert), delete (custom only)
- SQLite schema identical (WAL + busy_timeout); `playbook_history` undo log
- Concurrency: net/http spawns a goroutine per request, so webhook handling is concurrent
  by default (no event-loop serialization)

## Deliberate deviations

1. **Templates**: Jinja2 syntax (`{% %}` / `{{ }}` filters) rewritten as Go `html/template`
   (`{{range}}` / `{{if}}`). HTML, CSS and all client JS are otherwise reproduced verbatim.
2. **YAML key order**: the Go writer emits keys in struct order
   (`name, description, enabled, gate, locks, when, source, steps`) instead of Python's dict
   order. Valid YAML either way; both apps read each other's files.
3. **`iptables` backend**: stubbed (returns `error` status) — the Go port does not exec
   `iptables`. `firewall_backend: simulated` (the default) behaves identically.
4. **`funcs`/UTF-8**: `str()` mirrors Python's rendering for the field types we handle.

## Not ported (no behavioural equivalent needed)

- `app/core.py::_migrate_legacy_state` — a one-time 2026-08-08 migration of pre-refactor
  SQLite overrides. New DBs never contain those tables.
- `demo/` scripts and `README` of the Python repo.
