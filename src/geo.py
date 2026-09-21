from __future__ import annotations

from pathlib import Path

from parser import VlessNode


def apply_countries(nodes: list[VlessNode], database_path: Path) -> int:
    if not database_path.is_file():
        return 0

    import maxminddb

    classified = 0
    with maxminddb.open_database(str(database_path)) as reader:
        for node in nodes:
            if not node.exit_ip:
                continue
            record = reader.get(node.exit_ip) or {}
            country = record.get("country", {}).get("iso_code")
            if country:
                node.country = country.upper()
                classified += 1
    return classified
