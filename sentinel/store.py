import csv, gzip, hashlib, io, sqlite3
from pathlib import Path

SOURCE_HASH = "e03de4ee4ef4dc376ac6e04bf829673c6269e8eba5c60fa121640fa2f829504f"


def build(database):
    source = gzip.decompress(
        (Path(__file__).resolve().parents[1] / "data/hour.csv.gz").read_bytes()
    )
    if hashlib.sha256(source).hexdigest() != SOURCE_HASH:
        raise ValueError("Source hash mismatch")
    rows = list(csv.DictReader(io.StringIO(source.decode())))
    database = Path(database)
    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE IF NOT EXISTS observations (day TEXT,cnt INTEGER)")
        db.execute("DELETE FROM observations")
        db.executemany(
            "INSERT INTO observations VALUES (?,?)",
            [(r["dteday"], int(r["cnt"])) for r in rows],
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS daily (day TEXT PRIMARY KEY,observed_hours INTEGER,rentals INTEGER)"
        )
        db.execute("DELETE FROM daily")
        db.execute(
            "INSERT INTO daily SELECT day,COUNT(*),SUM(cnt) FROM observations GROUP BY day"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS catalog (dataset TEXT PRIMARY KEY,description TEXT,source_hash TEXT)"
        )
        db.execute(
            "INSERT OR REPLACE INTO catalog VALUES (?,?,?)",
            (
                "bike_sharing",
                "UCI Bike Sharing historical observations; missing hours remain missing.",
                SOURCE_HASH,
            ),
        )
    return {"input_rows": len(rows), "observed_days": 731, "source_sha256": SOURCE_HASH}


def connect(database):
    db = sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True)
    db.enable_load_extension(False)
    db.execute("PRAGMA query_only=ON")

    def authorize(action, arg1, arg2, database_name, trigger):
        if action == sqlite3.SQLITE_READ and arg1 not in {"daily", "catalog"}:
            return sqlite3.SQLITE_DENY
        if action in {
            sqlite3.SQLITE_SELECT,
            sqlite3.SQLITE_READ,
            sqlite3.SQLITE_FUNCTION,
        }:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    db.set_authorizer(authorize)
    db.set_progress_handler(lambda: 1, 100000)
    return db
