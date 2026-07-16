from example_test.DNS_test.Tor_client_dns import Tor_Client, TorResolveError

import asyncio
import concurrent.futures
import contextlib
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any


if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _json_default(value: Any):
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, default=_json_default) + "\n")


async def query_one(
    client: Tor_Client,
    hostname: str,
    *,
    sequence: int,
    hops_count: int,
    timeout: float,
    result_file: Path,
) -> dict[str, Any]:
    """顺序执行一次 RELAY_RESOLVE，并持久化完整请求记录。"""
    request_id = f"{client.name}:{sequence:06d}:{uuid.uuid4().hex}"
    started = asyncio.get_running_loop().time()

    try:
        result = await client.resolve_hostname(
            hostname,
            hops_count=hops_count,
            timeout=timeout,
            request_id=request_id,
        )
        elapsed = asyncio.get_running_loop().time() - started
        print(
            f"[DNS][OK] seq={sequence} request_id={request_id} "
            f"client={client.name} host={hostname} "
            f"answers={len(result.answers)} elapsed={elapsed:.3f}s"
        )
    except asyncio.TimeoutError as exc:
        elapsed = asyncio.get_running_loop().time() - started
        print(
            f"[DNS][TIMEOUT] seq={sequence} request_id={request_id} "
            f"client={client.name} host={hostname} elapsed={elapsed:.3f}s"
        )
        record = getattr(exc, "request_record", None)
    except TorResolveError as exc:
        elapsed = asyncio.get_running_loop().time() - started
        error_kind = "transient" if exc.transient else "nontransient"
        print(
            f"[DNS][ERROR] seq={sequence} request_id={request_id} "
            f"client={client.name} host={hostname} kind={error_kind} "
            f"elapsed={elapsed:.3f}s error={exc}"
        )
        record = getattr(exc, "request_record", None)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        elapsed = asyncio.get_running_loop().time() - started
        print(
            f"[DNS][FAIL] seq={sequence} request_id={request_id} "
            f"client={client.name} host={hostname} "
            f"elapsed={elapsed:.3f}s error={exc!r}"
        )
        record = getattr(exc, "request_record", None)
    else:
        record = client.get_resolve_record(request_id)

    if record is None:
        record = {
            "request_id": request_id,
            "client_id": client.name,
            "domain": hostname,
            "completion_status": "missing_record",
            "error_category": "instrumentation_error",
            "error_message": "client did not produce a completion record",
        }

    record["sequence"] = sequence
    snapshot = client.get_resolve_snapshot()
    record["post_request_pending_count"] = snapshot["pending_request_count"]
    record["post_request_active_count"] = snapshot["active_request_count"]
    record["post_request_clean"] = (
        record.get("stream_released") is True
        and record.get("pending_removed") is True
        and snapshot["pending_request_count"] == 0
        and snapshot["active_request_count"] == 0
    )
    append_jsonl(result_file, record)
    return record


async def stop_client(client: Tor_Client, protocol_task: asyncio.Task) -> None:
    with contextlib.suppress(Exception):
        await client.stop_protocol()
    if not protocol_task.done():
        protocol_task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await protocol_task


def build_summary(records: list[dict[str, Any]], clients: list[Tor_Client]) -> dict[str, Any]:
    total = len(records)
    successes = sum(r.get("completion_status") == "success" for r in records)
    clean = sum(r.get("post_request_clean") is True for r in records)
    aggregate = {
        "unmatched_response_count": 0,
        "duplicate_response_count": 0,
        "stream_id_conflict_count": 0,
        "unexpected_teardown_count": 0,
        "pending_request_count": 0,
        "active_request_count": 0,
    }
    for client in clients:
        snap = client.get_resolve_snapshot()
        for key in aggregate:
            aggregate[key] += int(snap.get(key, 0))

    success_rate = successes / total if total else 0.0
    acceptance = {
        "at_least_100_requests": total >= 100,
        "normal_domain_success_rate_ge_99pct": success_rate >= 0.99,
        "all_responses_uniquely_matched": (
            aggregate["unmatched_response_count"] == 0
            and aggregate["duplicate_response_count"] == 0
            and all(r.get("response_match_count", 0) == 1 for r in records if r.get("completion_status") == "success")
        ),
        "no_stream_id_conflict": aggregate["stream_id_conflict_count"] == 0,
        "no_unexpected_circuit_teardown": aggregate["unexpected_teardown_count"] == 0,
        "all_request_state_cleaned": clean == total and aggregate["pending_request_count"] == 0 and aggregate["active_request_count"] == 0,
    }
    acceptance["stage_passed"] = all(acceptance.values())
    return {
        "total_requests": total,
        "successful_requests": successes,
        "success_rate": success_rate,
        "cleaned_requests": clean,
        **aggregate,
        "completion_status_counts": {
            status: sum(r.get("completion_status") == status for r in records)
            for status in sorted({str(r.get("completion_status")) for r in records})
        },
        "acceptance": acceptance,
    }


async def main() -> None:
    loop = asyncio.get_running_loop()
    print("event-loop =>", type(loop))
    max_workers = int(os.environ.get("MAX_TLS_THREADS", "128"))
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix="tls-worker"
    ))

    directory_addr = os.environ.get("DIRECTORY_ADDR", "192.168.66.241:9030")
    node_addr = os.environ.get("NODE_ADDR", "192.168.66.242")
    clients_count = int(os.environ.get("CLIENTS_COUNT", "1"))
    base_port = int(os.environ.get("CLIENT_BASE_PORT", "9102"))
    hops_count = int(os.environ.get("HOPS", "3"))
    query_timeout = float(os.environ.get("DNS_TIMEOUT", "5.0"))
    query_count = int(os.environ.get("DNS_QUERY_COUNT", "100"))
    result_file = Path(os.environ.get("DNS_RESULT_FILE", "dns_single_request.jsonl"))
    summary_file = Path(os.environ.get("DNS_SUMMARY_FILE", "dns_single_request_summary.json"))

    raw_names = os.environ.get("DNS_NAMES", "www.qq.com")
    hostnames = [name.strip() for name in raw_names.split(",") if name.strip()]
    if not hostnames:
        raise ValueError("DNS_NAMES must contain at least one hostname")
    if query_count < 1:
        raise ValueError("DNS_QUERY_COUNT must be at least 1")

    os.environ["DIRECTORY_ADDR"] = directory_addr
    print(f"[Config] DIRECTORY_ADDR={directory_addr}")
    print(f"[Config] NODE_ADDR={node_addr}")
    print(f"[Config] CLIENTS_COUNT={clients_count}")
    print(f"[Config] CLIENT_BASE_PORT={base_port}")
    print(f"[Config] HOPS={hops_count}")
    print(f"[Config] DNS_TIMEOUT={query_timeout}s")
    print(f"[Config] DNS_QUERY_COUNT={query_count} (strictly sequential)")
    print(f"[Config] DNS_NAMES={hostnames}")
    print(f"[Config] DNS_RESULT_FILE={result_file}")

    clients: list[Tor_Client] = []
    protocol_tasks: list[asyncio.Task] = []
    records: list[dict[str, Any]] = []
    result_file.unlink(missing_ok=True)

    try:
        for index in range(clients_count):
            client = Tor_Client(
                name=f"dns-client{index}", host=node_addr,
                port=base_port + index, model="sim",
            )
            clients.append(client)
            protocol_tasks.append(asyncio.create_task(
                client.start_protocol(), name=f"{client.name}.protocol"
            ))

        await asyncio.gather(*(client.ready_to_send.wait() for client in clients))
        print(f"[Main] {len(clients)} client(s) ready; starting sequential DNS queries")

        # 严格顺序：任意时刻全局最多只有一个 DNS 请求。
        for sequence in range(1, query_count + 1):
            client = clients[(sequence - 1) % len(clients)]
            hostname = hostnames[(sequence - 1) % len(hostnames)]
            records.append(await query_one(
                client, hostname, sequence=sequence,
                hops_count=hops_count, timeout=query_timeout,
                result_file=result_file,
            ))

        summary = build_summary(records, clients)
        summary_file.parent.mkdir(parents=True, exist_ok=True)
        summary_file.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, default=_json_default),
            encoding="utf-8",
        )
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        print("[Main] Stage PASSED" if summary["acceptance"]["stage_passed"] else "[Main] Stage FAILED")
    finally:
        await asyncio.gather(*(
            stop_client(client, task)
            for client, task in zip(clients, protocol_tasks)
        ), return_exceptions=True)
        print("[Main] Finished")


if __name__ == "__main__":
    asyncio.run(main())
