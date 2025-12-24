# Semantic validation quickstart (external observability)

This guide shows how to produce the **Tor** vs **TorBox** semantic-validation artifacts when you only need externally observable protocol behavior. Each run emits JSONL logs plus a `run_meta.json` summarizing configuration and file paths.

## 1) Run the TorBox side (single or multi-round)
```bash
# Example: TorBox nodes + your own client
# Adjust DIRECTORY_ADDR / NODE_ADDR / TARGET_HOST / TARGET_PORT to match your deployment
# Optional: set EXP_LABEL to mark the run in the metadata
EXP_LABEL=TorBox \
RUN_ROUNDS=3 \    # set to 1 for a single run, >1 creates round_XXX subdirectories
LOG_DIR=exp/semantic_logs/torbox \
DIRECTORY_ADDR="192.168.66.241:9030" \
NODE_ADDR="192.168.66.242" \
TARGET_HOST="192.168.66.243" \
TARGET_PORT=8000 \
python -m app.senmantic\ test.semantic_runner
```

The runner prints the path to `run_meta.json`. Inside that file, `log_files.events` points to the JSONL event log for this run. When `RUN_ROUNDS>1`, a `multi_run_manifest.json` is written in `LOG_DIR` capturing all round metadata paths.

## 2) Run the Tor side once or multiple rounds
Use the same command but with `EXP_LABEL=Tor` (and any Tor-specific addresses you need). To mirror a multi-round TorBox run, set the same `RUN_ROUNDS` value:
```bash
EXP_LABEL=Tor \
RUN_ROUNDS=3 \
LOG_DIR=exp/semantic_logs/tor \
DIRECTORY_ADDR="192.168.66.241:9030" \
NODE_ADDR="192.168.66.242" \
TARGET_HOST="192.168.66.243" \
TARGET_PORT=8000 \
python -m app.senmantic\ test.semantic_runner
```

Again, note the `run_meta.json` path and the `log_files.events` entry.

## 3) Compare Tor vs TorBox (single or multi-round)
Point the analysis script at the two event logs (single run) **or** at the round root directories / manifest (multi-run). Examples:

Single run (JSONL or run_meta.json):
```bash
TOR_LOG=exp/semantic_logs/tor/events/events-123.jsonl
TORBOX_LOG=exp/semantic_logs/torbox/events/events-456.jsonl
python -m app.senmantic\ test.semantic_log_analysis \
  "$TOR_LOG" "$TORBOX_LOG" \
  --output-dir semantic_outputs
```

Multi-round using the generated `multi_run_manifest.json` (round count inferred):
```bash
python -m app.senmantic\ test.semantic_log_analysis \
  exp/semantic_logs/tor/multi_run_manifest.json \
  exp/semantic_logs/torbox/multi_run_manifest.json \
  --output-dir semantic_outputs_multi \
  --rounds 3
```

Multi-round using round directories directly (no manifest needed):
```bash
python -m app.senmantic\ test.semantic_log_analysis \
  exp/semantic_logs/tor \
  exp/semantic_logs/torbox \
  --output-dir semantic_outputs_multi \
  --rounds 3
```

Outputs in `semantic_outputs/` (or the directory you set):
- `metrics.txt`: aggregated control-plane ordering, SENDME stats, RELAY consistency, KS distance
- `round_XXX/metrics.txt` and plots per round
- `semantic_overview.png` / `semantic_overview.pdf`: plots derived from the real logs (aggregated or per-round)

## 4) Generate the SENDME CDF and protocol timelines

Both plotters now accept the same inputs as `semantic_log_analysis` (events JSONL, `run_meta.json`, round directory, or
`multi_run_manifest.json`). Use the optional `--tor-round/--torbox-round` flags to pick a specific round when a manifest or
multi-round directory is provided (default: last round).

Examples using manifests produced by `semantic_runner`:

```bash
python -m app.senmantic\ test.send\ me \
  --tor exp/semantic_logs/tor/multi_run_manifest.json \
  --torbox exp/semantic_logs/torbox/multi_run_manifest.json \
  --out semantic_outputs/plots \
  --tor-round 0 --torbox-round 0   # optional; omit to use the last round

python -m app.senmantic\ test.state \
  --tor exp/semantic_logs/tor/multi_run_manifest.json \
  --torbox exp/semantic_logs/torbox/multi_run_manifest.json \
  --out semantic_outputs/plots \
  --tor-round 0 --torbox-round 0   # optional
```

You can also point the scripts directly at a single `run_meta.json` or an events JSONL file if you only ran one round.

## Notes
- All defaults are set inside `semantic_runner.py` / `client_runner.py`; override via environment variables as shown above.
- Runs are single-user, single-circuit, single-stream by design, matching the semantic-validation scope.
- If you change payload size or hop count, keep both runs symmetric so the comparison remains meaningful.
