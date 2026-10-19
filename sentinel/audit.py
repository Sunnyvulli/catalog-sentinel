"""Application-layer hash chaining; not tamper-proof storage."""

import hashlib, json, os, threading
from datetime import datetime, timezone
from pathlib import Path


class Audit:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def append(self, role, method, params, status, seconds):
        with self.lock:
            previous = "0" * 64
            if self.path.exists():
                lines = self.path.read_text().splitlines()
                if lines:
                    previous = json.loads(lines[-1])["entry_sha256"]
            record = {
                "at_utc": datetime.now(timezone.utc).isoformat(),
                "role": role,
                "method": method,
                "arguments_sha256": hashlib.sha256(
                    json.dumps(params, sort_keys=True, default=str).encode()
                ).hexdigest(),
                "status": status,
                "seconds": seconds,
                "previous_sha256": previous,
            }
            record["entry_sha256"] = hashlib.sha256(
                json.dumps(record, sort_keys=True).encode()
            ).hexdigest()
            with self.path.open("a") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())


def verify(path):
    previous = "0" * 64
    count = 0
    for line in Path(path).read_text().splitlines():
        record = json.loads(line)
        claimed = record.pop("entry_sha256")
        if (
            record["previous_sha256"] != previous
            or hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
            != claimed
        ):
            raise ValueError("Audit chain changed")
        previous = claimed
        count += 1
    return count
