import random
from typing import List, Dict


def select_relays_by_role(file_path: str, num_guard: int, num_exit: int, num_middle: int) -> dict:
    relays = create_topology_by_consensus(file_path)
    selected = {"guard": [], "exit": [], "middle": []}
    used_fingerprints = set()

    # 选取 guard 节点
    guards = [r for r in relays if "Guard" in r.get("flags", [])]
    random.shuffle(guards)
    for r in guards:
        if len(selected["guard"]) >= num_guard:
            break
        if r["fingerprint"] not in used_fingerprints:
            selected["guard"].append(r)
            used_fingerprints.add(r["fingerprint"])

    # 选取 exit 节点
    exits = [r for r in relays if "Exit" in r.get("flags", [])]
    random.shuffle(exits)
    for r in exits:
        if len(selected["exit"]) >= num_exit:
            break
        if r["fingerprint"] not in used_fingerprints:
            selected["exit"].append(r)
            used_fingerprints.add(r["fingerprint"])

    # 选取 middle 节点（不包含已使用的 guard/exit，也不能含有 Guard 或 Exit 标志）
    middles = [
        r for r in relays
        if "Guard" not in r.get("flags", []) and "Exit" not in r.get("flags", []) and r["fingerprint"] not in used_fingerprints
    ]
    random.shuffle(middles)
    for r in middles:
        if len(selected["middle"]) >= num_middle:
            break
        selected["middle"].append(r)
        used_fingerprints.add(r["fingerprint"])

    return selected


def select_random_mix_with_minimum(file_path: str, total_num: int) -> list:
    relays = create_topology_by_consensus(file_path)
    if total_num < 2:
        raise ValueError("total_num must be at least 2 to include guard and exit")

    guards = [r for r in relays if "Guard" in r.get("flags", [])]
    exits = [r for r in relays if "Exit" in r.get("flags", [])]
    others = [r for r in relays if r not in guards and r not in exits]

    if not guards or not exits:
        raise ValueError("Consensus does not contain both Guard and Exit nodes")

    selected = []
    used_fingerprints = set()

    # 至少选一个 Guard 和一个 Exit
    guard = random.choice(guards)
    selected.append(guard)
    used_fingerprints.add(guard["fingerprint"])

    exit = random.choice([r for r in exits if r["fingerprint"] not in used_fingerprints])
    selected.append(exit)
    used_fingerprints.add(exit["fingerprint"])

    # 剩余从其他节点中选，确保不重复
    remaining = [
        r for r in relays if r["fingerprint"] not in used_fingerprints
    ]
    random.shuffle(remaining)

    for r in remaining:
        if len(selected) >= total_num:
            break
        selected.append(r)
        used_fingerprints.add(r["fingerprint"])

    return selected


def create_topology_by_consensus(file_path):
    """
    Read consensus file and create topology by parsing it into relays.

    :param file_path: Path to the consensus file
    :return: List of relay dictionaries
    """
    try:
        with open(file_path, 'r') as file:
            consensus_data = file.read()

        # Split the consensus data into individual router entries
        entries = consensus_data.split('\nr ')[1:]  # Split on 'r ' and skip first empty entry
        entries = ['r ' + entry for entry in entries]  # Prepend 'r ' to each entry

        # Parse entries into relays using relays_parse
        consensus = entries  # In this context, consensus is the list of entry strings
        relays = relays_parse(consensus)

        return relays

    except FileNotFoundError:
        print(f"Error: Consensus file not found at {file_path}")
        return []
    except Exception as e:
        print(f"Error processing consensus file: {str(e)}")
        return []


def create_topology_by_consesus_yaml(file_path):
    pass


def relays_parse(consensus) -> List[Dict]:
    """
    Parse the cached consensus and return a list of relay dicts.
    Each dict contains: fingerprint, nickname, ip, or_port, dir_port, flags.
    """
    relays = []
    for node in consensus:
        node_str = node.__str__()
        relay_info = parse_single_consensus_entry(node_str)
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
            relay["digest"] = parts[3]
            relay["service_key"] = parts[3]
            relay["ip"] = parts[6]
            relay["or_port"] = int(parts[7])
            relay["dir_port"] = int(parts[8])

        elif line.startswith('s '):
            relay["flags"] = line[2:].split()

        elif line.startswith('p '):
            relay["exit_policy"] = line[2:].strip()

        elif line.startswith('v '):
            relay["version"] = line[2:].strip()

        elif line.startswith('pr '):
            relay["protocols"] = line[3:].strip()

        elif line.startswith('w '):
            parts = line[2:].split()
            for part in parts:
                if part.startswith('Bandwidth='):
                    relay["bandwidth"] = int(part.split('=')[1])

    return relay



if __name__ == "__main__":
    relays = create_topology_by_consensus(file_path="D:\project\Oniverse_refactor/2023-01-01-00-00-00-consensus")
    print(relays)