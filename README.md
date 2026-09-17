# Emulator

Emulator is a research-oriented Python framework for experimenting with anonymous-communication networks. The active `refactor` branch contains a simplified Tor protocol implementation, Loopix components, Sphinx packet primitives, network-condition controls, and experiment instrumentation.

> [!IMPORTANT]
> This repository is an experimental emulator, not a drop-in Tor implementation and not a production anonymity tool. Do not rely on it to protect real users or sensitive traffic.

## What it provides

- **Tor-style protocol experiments** — directory, relay, client, circuit, stream, cell, flow-control, and path-selection components.
- **Mix-network experiments** — Loopix nodes and Sphinx packet-processing primitives.
- **Controlled network conditions** — bandwidth limiting, geographic-delay injection, topology helpers, and DNS utilities.
- **Observability** — structured JSONL event logging, resource probes, stream tracking, and analysis scripts.
- **Reproducible scenarios** — latency, scalability, deployment, file-transfer, and semantic-comparison experiments under `example_test/`.

The implementation intentionally models only selected protocol behavior. See [`network_src/TorCore/readme.md`](network_src/TorCore/readme.md) for the current Tor simplifications.

## Repository layout

| Path | Purpose |
| --- | --- |
| `network_src/TorCore/` | Simplified Tor directory, relay, client, circuit, cell, stream, and socket logic |
| `network_src/Loopix/` | Loopix client, provider, mix node, directory, and data-management code |
| `src/sphinxmix/` | Sphinx/Ultrix packet primitives used by mix-network experiments |
| `tools/` | Cryptography, packet I/O, logging, monitoring, and network-condition helpers |
| `example_test/` | End-to-end research scenarios and analysis scripts |
| `test_circid.py` | Focused circuit-ID allocation tests |
| `gen_compose.py` | Utility for generating a Tor relay Docker Compose topology |

## Requirements

- Python 3.10 or newer
- Linux is recommended for larger socket- and network-oriented experiments
- Docker and Docker Compose are optional and only needed for generated relay topologies

Some analysis examples use scientific and plotting packages; these are included in `requirements.txt` alongside the runtime dependencies.

## Installation

```bash
git clone https://github.com/suoxiaotian12138/Emulator.git
cd Emulator
git switch refactor

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Quick checks

Run the focused circuit-ID tests:

```bash
python -m pytest -q test_circid.py
```

Generate a sample Docker Compose file without starting containers:

```bash
python gen_compose.py --guards 1 --middles 1 --exits 1 --output docker-compose.yml
```

Many end-to-end scenarios start multiple local services or connect to an external target. Read the scenario configuration before running it. In particular, scripts commonly use the `DIRECTORY_ADDR` environment variable:

```bash
export DIRECTORY_ADDR=127.0.0.1:8080
```

The semantic-validation workflow is documented in [`example_test/senmantic test/SEMANTIC_RUN.md`](example_test/senmantic%20test/SEMANTIC_RUN.md). The directory name is retained for compatibility with the current branch.

## Development status

Development currently happens on the `refactor` branch. APIs, experiment scripts, and protocol coverage may change without notice. Known repository-cleanup and packaging work is being tracked incrementally so protocol changes remain reviewable.

Contributions are welcome through issues and pull requests. When reporting a problem, include the branch/commit, Python version, operating system, scenario, and a minimal log excerpt with secrets or identifying traffic removed.

## Security and research ethics

The `Attack/` and traffic-analysis utilities are intended for controlled research, testing, and defensive evaluation. Use them only on systems and data you own or are explicitly authorized to test. Never expose generated keys, packet captures, experiment logs, or real-user traffic in an issue.

For a suspected vulnerability, please open a minimal private report through GitHub's security-reporting interface if enabled; otherwise contact the maintainer before publishing exploit details.

## License

Licensed under the [Apache License 2.0](LICENSE). Before redistributing third-party material, verify and preserve any upstream notices that apply to it.

