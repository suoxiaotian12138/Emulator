# directory.py
from __future__ import annotations
import asyncio
from typing import Dict, List, Literal, Optional
from datetime import datetime
from tools.Packet.packet_TCP import send_tcp, listen_to_tcp, ByteBuffer, handle_tcp
from examples.Tor_simplified.Tor_base import Tor_base
from queue import Queue

Backend = Literal["stem", "torpy"]


class Directory_local(Tor_base):
    def __init__(self, name: str, host: str, port: int):
        super().__init__(name, host, port)
        self.output_buffer = Queue()
        self.node_descriptors = []


    async def start_protocol(self):
        # self.tasks['routing_task'] = asyncio.create_task(self.routing_request())
        self.tasks['listener_task'] = asyncio.create_task(self.listener())
        self.tasks['process_task'] = asyncio.create_task(self.process())
        # self.tasks['periodic_send_task'] = asyncio.create_task(self.periodic_make_stream(interval=self.config.EXP_PARAMS_LOOPS))

        await asyncio.gather(*self.tasks.values())

    async def process(self):
        import binascii
        while True:
            obj = await self.buffer.extract_by_size()
            if obj is None:
                break
            self.print(binascii.hexlify(obj))

    def vote(self):
        """
        Not implemented yet, only simulated through a directory server
        Communication between directory authorities, voting every hour to form a consensus document
        :return:
        """
        pass




class Directory:
    """Download a consensus and extract relay information."""

    def __init__(self) -> None:
        self._consensus = None  # raw consensus object

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def fetch_consensus(self, *, endpoints: Optional[List] = None) -> None:
        """
        Download the latest consensus and cache it in `self._consensus`.

        Parameters
        ----------
        endpoints : optional
            A list of specific directory mirrors or authorities to query
            (only meaningful for the Stem backend). If omitted Stem falls
            back to its baked‑in list of “fallback dir” nodes.  Torpy always
            rotates over the current authorities automatically.
        """
        # Stem returns a generator; the first (and only) element is the doc
        from stem.descriptor.remote import get_consensus

        result = get_consensus(endpoints=endpoints, timeout=300).run()  # -> list
        print(result[0].__str__())
        print(type(result[0]))
        self._consensus = result

    @property
    def valid_after(self) -> datetime | None:
        """Returns the consensus ‘valid‑after’ timestamp."""
        if not self._consensus:
            return None
        return getattr(self._consensus, "valid_after", None)

    def relays_parse(self) -> List[Dict]:
        """
        Parse the cached consensus and return a list of relay dicts.

        Each dict contains: fingerprint, nickname, ip, or_port, dir_port, flags.
        """
        if self._consensus is None:
            self.fetch_consensus()

        relays = []
        for node in self._consensus:
            node_str = node.__str__()
            relay_info = parse_single_consensus_entry(node_str)
            relay_info = {
                "exit_policy": node.exit_policy.summary() if node.exit_policy else "none",
                "digest": node.digest,
                "dir_port": node.dir_port,
                "service_key": node.identifier,  # Ed25519 base64 string
                "nickname": node.nickname,
                "ip": node.address,
                "or_port": node.or_port,
                "flags": list(node.flags),
            }
            relays.append(relay_info)

        return relays


def parse_single_consensus_entry(entry_str: str) -> dict:
    """
    Parse a single router consensus block into a dictionary.

    :param entry_str: Multiline string representing a single consensus entry.
    :return: Dictionary with parsed fields.
    """
    relay = {}
    lines = entry_str.strip().splitlines()

    for line in lines:
        if line.startswith('r '):
            parts = line.strip().split()
            relay["nickname"] = parts[1]
            relay["fingerprint"] = parts[2]
            relay["digest"] = parts[2]
            relay["service_key"] = parts[3]
            relay["ip"] = parts[6]
            relay["or_port"] = int(parts[7])
            relay["dir_port"] = int(parts[8])

        elif line.startswith('s '):
            relay["flags"] = line[2:].split()

        elif line.startswith('p '):
            relay["exit_policy"] = line[2:].strip()

        elif line.startswith('v '):
            relay["tor_version"] = line[2:].strip()

        elif line.startswith('pr '):
            relay["protocols"] = line[3:].strip()

        elif line.startswith('w '):
            parts = line[2:].split()
            for part in parts:
                if part.startswith('Bandwidth='):
                    relay["bandwidth"] = int(part.split('=')[1])

    return relay


import re


def parse_full_consensus(consensus_text: str):
    """
    Parses a full Tor consensus file into header, router blocks, footer, and directory signatures.

    :param consensus_text: The full consensus file text as a string.
    :return: A dictionary with 'header', 'routers', 'footer', and 'signatures'.
    """
    lines = consensus_text.strip().splitlines()
    header_lines = []
    router_entries = []
    footer_lines = []
    signatures = []

    current_router = []
    in_router_section = False
    in_footer = False
    current_signature = []

    for line in lines:
        if line.startswith("r ") and not in_footer:
            if current_router:
                router_entries.append("\n".join(current_router))
                current_router = []
            current_router.append(line)
            in_router_section = True

        elif line.startswith("directory-footer"):
            if current_router:
                router_entries.append("\n".join(current_router))
                current_router = []
            in_router_section = False
            in_footer = True
            footer_lines.append(line)

        elif in_footer:
            footer_lines.append(line)
            if line.startswith("directory-signature "):
                if current_signature:
                    signatures.append(_parse_signature_block(current_signature))
                    current_signature = []
                current_signature = [line]
            elif line.startswith("-----BEGIN SIGNATURE-----"):
                current_signature.append(line)
            elif line.startswith("-----END SIGNATURE-----"):
                current_signature.append(line)
                signatures.append(_parse_signature_block(current_signature))
                current_signature = []
            elif current_signature:
                current_signature.append(line)

        elif in_router_section:
            current_router.append(line)

        else:
            header_lines.append(line)

    if current_router:
        router_entries.append("\n".join(current_router))

    return {
        "header": "\n".join(header_lines),
        "routers": router_entries,
        "footer": "\n".join(footer_lines),
        "signatures": signatures
    }


def _parse_signature_block(sig_lines):
    """
    Parses a directory-signature block.
    """
    header = sig_lines[0].strip()
    match = re.match(r"directory-signature (\S+) (\S+)", header)
    fingerprint, digest = match.groups() if match else ("?", "?")
    sig_block = "\n".join(sig_lines[1:])
    return {
        "fingerprint": fingerprint,
        "digest": digest,
        "signature": sig_block
    }


if __name__ == "__main__":
    with open("consesus.txt", "r", encoding="utf-8") as f:
        consensus = f.read()

#     logging.basicConfig(level=logging.INFO)
#
#     # --- Stem backend -------------------------------------------------- #
#     d_stem = Directory()
#     d_stem.fetch_consensus()  # downloads in ~1 s
#     guards = [r for r in d_stem.relays_parse() if "Guard" in r["flags"]]
#     print(f"[Stem] total relays={len(d_stem.relays_parse())}  guards={len(guards)}")


