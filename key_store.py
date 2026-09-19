# BRMods key store (SQLite) - web panel edition.
# Same schema/logic as workbrmod/key_store.py, plus:
#   - DB path configurable via KEYSTORE_DB (default ./data/brmod_keys.db)
#   - `note` column (customer / discord / remark) with safe migration
#   - export_json / import_records for syncing with the local auth-swap server
#   - CLI: python key_store.py create NAME PACK [note] | list | export FILE | import FILE
#
# Convention (per skill): user = TÊN key, pass = "1" fixed,
# packs = 1/3/7/30/9999 days (9999 = LIFETIME), hwid "*" = no bind.
import json
import os
import sqlite3
import sys
import time

DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "brmod_keys.db")
DB = os.environ.get("KEYSTORE_DB", DEFAULT_DB)
PACKS = {1, 3, 7, 30, 9999}
LIFETIME_UNIX = 4102444799  # 2099-12-31 23:59:59


def connect():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB, timeout=10)
    c.execute(
        """CREATE TABLE IF NOT EXISTS keys(
            name       TEXT PRIMARY KEY,
            pack       INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            status     TEXT DEFAULT 'active',
            hwid       TEXT NOT NULL DEFAULT '*',
            note       TEXT DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL)"""
    )
    # safe migration: add `note` if missing
    cols = [r[1] for r in c.execute("PRAGMA table_info(keys)").fetchall()]
    if "note" not in cols:
        c.execute("ALTER TABLE keys ADD COLUMN note TEXT DEFAULT ''")
    c.commit()
    return c


def _now():
    return int(time.time())


def _row_to_dict(r):
    return {
        "name": r[0], "pack": r[1], "expires_at": r[2], "status": r[3],
        "hwid": r[4], "note": r[5] if len(r) > 5 else "", "created_at": r[6],
        "updated_at": r[7],
    }


def get(name):
    c = connect()
    row = c.execute(
        "SELECT name,pack,expires_at,status,hwid,note,created_at,updated_at "
        "FROM keys WHERE name=?", (str(name).strip(),)
    ).fetchone()
    c.close()
    return _row_to_dict(row) if row else None


def create(name, pack, note=""):
    name = (name or "").strip()
    if not name or len(name) > 64:
        return False, "invalid name", None
    if pack not in PACKS:
        return False, "invalid pack (1/3/7/30/9999)", None
    c = connect()
    if c.execute("SELECT name FROM keys WHERE name=?", (name,)).fetchone():
        c.close()
        return False, "key %r already exists (use /grant to extend)" % name, None
    now = _now()
    exp = LIFETIME_UNIX if pack >= 9999 else now + pack * 86400
    c.execute(
        "INSERT INTO keys(name,pack,expires_at,status,hwid,note,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (name, pack, exp, "active", "*", note or "", now, now),
    )
    c.commit()
    row = get(name)
    c.close()
    return True, "created", row


def grant(name, pack):
    if pack not in PACKS:
        return False, "invalid pack (1/3/7/30/9999)", None
    row = get(name)
    if not row:
        return False, "key not found", None
    c = connect()
    now = _now()
    if pack >= 9999:
        exp = LIFETIME_UNIX
    else:
        base = max(now, row["expires_at"]) if row["expires_at"] < LIFETIME_UNIX else now
        exp = base + pack * 86400
    c.execute(
        "UPDATE keys SET pack=?, expires_at=?, status='active', updated_at=? WHERE name=?",
        (pack if pack >= 9999 else row["pack"], exp, now, name),
    )
    c.commit()
    c.close()
    return True, "granted +%dd" % pack, get(name)


def set_status(name, status):
    row = get(name)
    if not row:
        return False, "key not found", None
    c = connect()
    c.execute("UPDATE keys SET status=?, updated_at=? WHERE name=?",
              (status, _now(), name))
    c.commit()
    c.close()
    return True, "status=%s" % status, get(name)


def set_note(name, note):
    row = get(name)
    if not row:
        return False, "key not found", None
    c = connect()
    c.execute("UPDATE keys SET note=?, updated_at=? WHERE name=?", (note or "", _now(), name))
    c.commit()
    c.close()
    return True, "note updated", get(name)


def bind(name, hwid):
    c = connect()
    c.execute("UPDATE keys SET hwid=?, updated_at=? WHERE name=?", (hwid, _now(), name))
    c.commit()
    c.close()


def reset(name):
    row = get(name)
    if not row:
        return False, "key not found", None
    set_status(name, "active")
    bind(name, "*")
    return True, "reset", get(name)


def check(name, hwid):
    row = get(name)
    if not row:
        return False, "key not found", None
    if row["status"] != "active":
        return False, "status=%s" % row["status"], None
    if row["hwid"] == "*":
        pass
    elif not row["hwid"]:
        bind(name, hwid)
        row["hwid"] = hwid
    elif row["hwid"] != hwid:
        return False, "hwid mismatch", None
    if row["expires_at"] >= LIFETIME_UNIX:
        return True, "lifetime", None
    if row["expires_at"] < _now():
        return False, "expired", None
    import datetime
    dt = datetime.datetime.fromtimestamp(row["expires_at"])
    return True, "ok until %s" % dt.strftime("%Y-%m-%d %H:%M:%S"), dt.strftime("%Y-%m-%d %H:%M:%S")


def list_keys(status=None):
    c = connect()
    if status:
        rows = c.execute(
            "SELECT name,pack,expires_at,status,hwid,note,created_at,updated_at "
            "FROM keys WHERE status=? ORDER BY created_at DESC", (status,)
        ).fetchall()
    else:
        rows = c.execute(
            "SELECT name,pack,expires_at,status,hwid,note,created_at,updated_at "
            "FROM keys ORDER BY created_at DESC"
        ).fetchall()
    c.close()
    return [_row_to_dict(r) for r in rows]


def stats():
    rows = list_keys()
    active = [r for r in rows if r["status"] == "active"]
    now = _now()
    exp_soon = [r for r in active if 0 < r["expires_at"] < LIFETIME_UNIX
                and r["expires_at"] - now < 3 * 86400]
    return {
        "total": len(rows),
        "active": len(active),
        "revoked": len(rows) - len(active),
        "expiring_soon": len(exp_soon),
        "by_pack": {str(p): sum(1 for r in active if r["pack"] == p) for p in sorted(PACKS)},
    }


def export_json():
    """All keys as JSON-serializable list (for web Export / local sync)."""
    return [json.loads(json.dumps(r, ensure_ascii=False)) for r in list_keys()]


def import_records(records):
    """Upsert-create rows preserving expires_at/status/hwid/note.
    Returns {imported: [...], skipped: [...]}."""
    out = {"imported": [], "skipped": []}
    c = connect()
    for r in records or []:
        name = str(r.get("name", "")).strip()
        if not name:
            continue
        if c.execute("SELECT name FROM keys WHERE name=?", (name,)).fetchone():
            out["skipped"].append(name)
            continue
        try:
            pack = int(r.get("pack") or 0)
        except Exception:
            pack = 0
        if pack not in PACKS:
            out["skipped"].append(name)
            continue
        now = _now()
        exp = int(r.get("expires_at") or 0)
        if not exp:
            exp = LIFETIME_UNIX if pack >= 9999 else now + pack * 86400
        status = r.get("status") if r.get("status") in ("active", "revoked") else "active"
        hwid = str(r.get("hwid") or "*")
        note = str(r.get("note") or "")
        c.execute(
            "INSERT OR REPLACE INTO keys(name,pack,expires_at,status,hwid,note,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (name, pack, exp, status, hwid, note, now, now),
        )
        out["imported"].append(name)
    c.commit()
    c.close()
    return out


def main_cli():
    """python key_store.py create NAME PACK [note] | list | export FILE | import FILE"""
    args = sys.argv[1:]
    if not args:
        print(__doc__.split("CLI:")[1].strip())
        return 0
    cmd = args[0]
    if cmd == "create" and len(args) >= 3:
        ok, msg, row = create(args[1], int(args[2]), args[3] if len(args) > 3 else "")
        print(ok, msg)
        if row:
            print(row)
        return 0 if ok else 1
    if cmd == "list":
        rows = list_keys()
        print("%-20s %6s %14s %10s %-12s %s" % ("NAME", "PACK", "EXPIRES_AT", "STATUS", "HWID", "NOTE"))
        for r in rows:
            exp = "LIFETIME" if r["expires_at"] >= LIFETIME_UNIX else r["expires_at"]
            print("%-20s %6d %14s %10s %-12s %s" % (r["name"], r["pack"], exp, r["status"], r["hwid"][:10], r["note"][:30]))
        return 0
    if cmd == "export" and len(args) >= 2:
        with open(args[1], "w", encoding="utf-8") as f:
            json.dump(export_json(), f, ensure_ascii=False, indent=2)
        print("exported %d keys -> %s" % (len(list_keys()), args[1]))
        return 0
    if cmd == "import" and len(args) >= 2:
        with open(args[1], "r", encoding="utf-8") as f:
            records = json.load(f)
        out = import_records(records)
        print("imported: %d  skipped: %d" % (len(out["imported"]), len(out["skipped"])))
        return 0
    print("unknown command. usage:", __doc__.split("CLI:")[1].strip())
    return 1


if __name__ == "__main__":
    sys.exit(main_cli())