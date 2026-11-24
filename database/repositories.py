"""Data-access functions. Every statement uses bound parameters (no string-built values)."""
import json
from datetime import datetime, timedelta, timezone

from database.db_connection import get_db, utcnow

JSON_FIELDS = {"metadata", "preprocess_config", "preprocess_summary", "feature_schema",
               "training_config", "metrics", "config", "raw_data"}


def _ser(row):
    """Normalise a DB row: datetimes -> ISO-8601 UTC strings, JSON text -> objects."""
    if row is None:
        return None
    out = {}
    for k, v in row.items():
        if isinstance(v, datetime):
            v = v.strftime("%Y-%m-%dT%H:%M:%SZ")
        elif k.endswith("_at") or k == "timestamp":
            if isinstance(v, str) and len(v) >= 19 and v[10] in " T":
                v = v[:10] + "T" + v[11:19] + "Z"
        elif k in JSON_FIELDS and isinstance(v, str):
            try:
                v = json.loads(v)
            except ValueError:
                pass
        out[k] = v
    return out


def _many(rows):
    return [_ser(r) for r in rows]


def _dump(obj):
    return None if obj is None else json.dumps(obj, default=str)


def page_args(page, per_page, max_per=200):
    try:
        page = max(1, int(page or 1))
        per_page = min(max_per, max(1, int(per_page or 25)))
    except (TypeError, ValueError):
        page, per_page = 1, 25
    return page, per_page, (page - 1) * per_page


def day_start(s):
    return f"{s} 00:00:00" if s and len(s) == 10 else s


def day_end(s):
    return f"{s} 23:59:59" if s and len(s) == 10 else s


# ============================================================ users
class Users:
    @staticmethod
    def get(user_id):
        return _ser(get_db().query_one("SELECT * FROM users WHERE user_id=%s", (user_id,)))

    @staticmethod
    def find_by_login(login):
        return _ser(get_db().query_one(
            "SELECT * FROM users WHERE LOWER(username)=LOWER(%s) OR LOWER(email)=LOWER(%s)", (login, login)))

    @staticmethod
    def count():
        return get_db().query_one("SELECT COUNT(*) AS n FROM users")["n"]

    @staticmethod
    def create(username, email, password_hash, role="analyst"):
        uid, _ = get_db().execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (%s,%s,%s,%s,%s)",
            (username, email, password_hash, role, utcnow()))
        return uid

    @staticmethod
    def update_password(user_id, password_hash):
        get_db().execute("UPDATE users SET password_hash=%s WHERE user_id=%s", (password_hash, user_id))

    @staticmethod
    def touch_login(user_id):
        get_db().execute("UPDATE users SET last_login_at=%s WHERE user_id=%s", (utcnow(), user_id))


# ============================================================ datasets
class Datasets:
    @staticmethod
    def create(**f):
        cols = ["dataset_name", "original_filename", "dataset_type", "file_path", "file_size", "uploaded_by",
                "row_count", "column_count", "label_column", "processing_status", "metadata"]
        vals = [(_dump(f[c]) if c == "metadata" else f.get(c)) for c in cols]
        did, _ = get_db().execute(
            f"INSERT INTO datasets ({','.join(cols)}, created_at) VALUES ({','.join(['%s'] * len(cols))}, %s)",
            vals + [utcnow()])
        return did

    @staticmethod
    def get(dataset_id):
        return _ser(get_db().query_one("SELECT * FROM datasets WHERE dataset_id=%s", (dataset_id,)))

    @staticmethod
    def list():
        rows = get_db().query_all(
            "SELECT dataset_id, dataset_name, original_filename, dataset_type, file_size, row_count, column_count, "
            "label_column, processing_status, error_message, created_at FROM datasets ORDER BY dataset_id DESC")
        return _many(rows)

    @staticmethod
    def update(dataset_id, **fields):
        if not fields:
            return
        sets, vals = [], []
        for k, v in fields.items():
            if k not in {"label_column", "processing_status", "preprocess_config", "preprocess_summary",
                         "error_message", "metadata", "dataset_name"}:
                raise ValueError(f"column {k} not updatable")
            sets.append(f"{k}=%s")
            vals.append(_dump(v) if k in JSON_FIELDS else v)
        get_db().execute(f"UPDATE datasets SET {', '.join(sets)} WHERE dataset_id=%s", vals + [dataset_id])

    @staticmethod
    def delete(dataset_id):
        get_db().execute("DELETE FROM datasets WHERE dataset_id=%s", (dataset_id,))

    @staticmethod
    def count_processing():
        return get_db().query_one(
            "SELECT COUNT(*) AS n FROM datasets WHERE processing_status='Preprocessing'")["n"]


# ============================================================ models / jobs
class Models:
    COLS = ("model_id, algorithm, dataset_id, dataset_name, version, model_path, pipeline_path, feature_schema, "
            "training_config, accuracy, precision_score, recall_score, f1_score, fpr, fnr, metrics, "
            "training_seconds, prediction_seconds, threshold, is_active, created_by, created_at")

    @staticmethod
    def next_version(algorithm, dataset_id):
        row = get_db().query_one(
            "SELECT MAX(version) AS v FROM model_registry WHERE algorithm=%s AND dataset_id=%s", (algorithm, dataset_id))
        return (row["v"] or 0) + 1

    @staticmethod
    def create(**f):
        m = f["metrics"]
        mal = m["malicious"]
        mid, _ = get_db().execute(
            "INSERT INTO model_registry (algorithm, dataset_id, dataset_name, version, model_path, pipeline_path, "
            "feature_schema, training_config, accuracy, precision_score, recall_score, f1_score, fpr, fnr, metrics, "
            "training_seconds, prediction_seconds, threshold, is_active, created_by, created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,%s,%s)",
            (f["algorithm"], f["dataset_id"], f["dataset_name"], f["version"], f["model_path"], f["pipeline_path"],
             _dump(f["feature_schema"]), _dump(f["training_config"]), m["accuracy"], mal["precision"], mal["recall"],
             mal["f1"], m["false_positive_rate"], m["false_negative_rate"], _dump(m), f["training_seconds"],
             f["prediction_seconds"], f.get("threshold", 0.5), f.get("created_by"), utcnow()))
        return mid

    @staticmethod
    def get(model_id):
        return _ser(get_db().query_one(f"SELECT {Models.COLS} FROM model_registry WHERE model_id=%s", (model_id,)))

    @staticmethod
    def list(dataset_id=None, algorithm=None):
        sql, p = f"SELECT {Models.COLS} FROM model_registry WHERE 1=1", []
        if dataset_id:
            sql += " AND dataset_id=%s"
            p.append(dataset_id)
        if algorithm:
            sql += " AND algorithm=%s"
            p.append(algorithm)
        return _many(get_db().query_all(sql + " ORDER BY model_id DESC", p))

    @staticmethod
    def active():
        return _ser(get_db().query_one(f"SELECT {Models.COLS} FROM model_registry WHERE is_active=1 LIMIT 1"))

    @staticmethod
    def activate(model_id):
        with get_db().transaction() as tx:
            tx.execute("UPDATE model_registry SET is_active=0 WHERE is_active=1")
            tx.execute("UPDATE model_registry SET is_active=1 WHERE model_id=%s", (model_id,))


class Jobs:
    @staticmethod
    def create(dataset_id, algorithm, config, user_id):
        jid, _ = get_db().execute(
            "INSERT INTO training_jobs (dataset_id, algorithm, job_status, progress, progress_message, config, "
            "created_by, created_at) VALUES (%s,%s,'Pending',0,'Queued',%s,%s,%s)",
            (dataset_id, algorithm, _dump(config), user_id, utcnow()))
        return jid

    @staticmethod
    def get(job_id):
        return _ser(get_db().query_one(
            "SELECT j.*, d.dataset_name FROM training_jobs j LEFT JOIN datasets d ON d.dataset_id=j.dataset_id "
            "WHERE j.job_id=%s", (job_id,)))

    @staticmethod
    def list(limit=30):
        return _many(get_db().query_all(
            "SELECT j.*, d.dataset_name FROM training_jobs j LEFT JOIN datasets d ON d.dataset_id=j.dataset_id "
            "ORDER BY j.job_id DESC LIMIT %s", (limit,)))

    @staticmethod
    def update(job_id, **f):
        allowed = {"job_status", "progress", "progress_message", "error_message", "model_id", "started_at",
                   "completed_at"}
        sets, vals = [], []
        for k, v in f.items():
            if k not in allowed:
                raise ValueError(k)
            sets.append(f"{k}=%s")
            vals.append(v)
        get_db().execute(f"UPDATE training_jobs SET {', '.join(sets)} WHERE job_id=%s", vals + [job_id])

    @staticmethod
    def fail_interrupted():
        """Jobs left Pending/Running by a previous process can never finish."""
        get_db().execute(
            "UPDATE training_jobs SET job_status='Failed', error_message='Interrupted by application restart', "
            "completed_at=%s WHERE job_status IN ('Pending','Running')", (utcnow(),))
        get_db().execute(
            "UPDATE datasets SET processing_status='Failed', error_message='Interrupted by application restart' "
            "WHERE processing_status='Preprocessing'")

    @staticmethod
    def running_count():
        return get_db().query_one(
            "SELECT COUNT(*) AS n FROM training_jobs WHERE job_status IN ('Pending','Running')")["n"]


# ============================================================ traffic / predictions / alerts
SORT_COLUMNS = {"timestamp": "l.timestamp", "source_ip": "l.source_ip", "destination_ip": "l.destination_ip",
                "protocol": "l.protocol", "packet_size": "l.packet_size", "prediction": "p.prediction_result",
                "confidence": "p.confidence_score", "log_id": "l.log_id"}

TRAFFIC_SELECT = (
    "SELECT l.log_id, l.timestamp, l.source_ip, l.destination_ip, l.protocol, l.packet_size, l.source, l.dataset_id, "
    "p.prediction_id, p.model_name, p.model_version, p.prediction_result, p.confidence_score, "
    "p.malicious_probability, a.alert_id, a.threat_level, a.status AS alert_status "
    "FROM network_logs l JOIN predictions p ON p.log_id=l.log_id LEFT JOIN alerts a ON a.prediction_id=p.prediction_id")


class Traffic:
    @staticmethod
    def insert_detection(tx, log, pred, alert):
        """Insert log + prediction (+ alert) inside the caller's transaction."""
        log_id, _ = tx.execute(
            "INSERT INTO network_logs (user_id, timestamp, source_ip, destination_ip, protocol, packet_size, "
            "raw_data, source, dataset_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (log.get("user_id"), log["timestamp"], log["source_ip"], log["destination_ip"], log["protocol"],
             log["packet_size"], _dump(log["raw_data"]), log["source"], log.get("dataset_id")))
        pred_id, _ = tx.execute(
            "INSERT INTO predictions (log_id, model_id, model_name, model_version, prediction_result, "
            "confidence_score, malicious_probability, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (log_id, pred["model_id"], pred["model_name"], pred["model_version"], pred["prediction_result"],
             pred["confidence_score"], pred["malicious_probability"], log["timestamp"]))
        alert_id = None
        if alert:
            alert_id, _ = tx.execute(
                "INSERT INTO alerts (prediction_id, alert_type, threat_level, alert_message, status, created_at) "
                "VALUES (%s,%s,%s,%s,'Open',%s)",
                (pred_id, alert["alert_type"], alert["threat_level"], alert["alert_message"], log["timestamp"]))
        return log_id, pred_id, alert_id

    @staticmethod
    def _filters(f):
        where, p = [], []
        if f.get("q"):
            like = f"%{f['q']}%"
            where.append("(l.source_ip LIKE %s OR l.destination_ip LIKE %s OR l.protocol LIKE %s)")
            p += [like, like, like]
        if f.get("ip"):
            where.append("(l.source_ip=%s OR l.destination_ip=%s)")
            p += [f["ip"], f["ip"]]
        if f.get("protocol"):
            where.append("UPPER(l.protocol)=UPPER(%s)")
            p.append(f["protocol"])
        if f.get("result") in ("Normal", "Malicious"):
            where.append("p.prediction_result=%s")
            p.append(f["result"])
        if f.get("date_from"):
            where.append("l.timestamp >= %s")
            p.append(day_start(f["date_from"]))
        if f.get("date_to"):
            where.append("l.timestamp <= %s")
            p.append(day_end(f["date_to"]))
        if f.get("model"):
            where.append("p.model_name=%s")
            p.append(f["model"])
        return (" WHERE " + " AND ".join(where)) if where else "", p

    @staticmethod
    def list(filters, page=1, per_page=25, sort="log_id", order="desc"):
        page, per_page, offset = page_args(page, per_page)
        where, p = Traffic._filters(filters)
        col = SORT_COLUMNS.get(sort, "l.log_id")
        direction = "ASC" if str(order).lower() == "asc" else "DESC"
        total = get_db().query_one(
            "SELECT COUNT(*) AS n FROM network_logs l JOIN predictions p ON p.log_id=l.log_id" + where, p)["n"]
        rows = get_db().query_all(f"{TRAFFIC_SELECT}{where} ORDER BY {col} {direction}, l.log_id DESC LIMIT %s OFFSET %s",
                                  p + [per_page, offset])
        return {"items": _many(rows), "total": total, "page": page, "per_page": per_page}

    @staticmethod
    def recent(limit=15, since_id=None):
        sql, p = TRAFFIC_SELECT, []
        if since_id:
            sql += " WHERE l.log_id > %s"
            p.append(since_id)
        return _many(get_db().query_all(sql + " ORDER BY l.log_id DESC LIMIT %s", p + [limit]))

    @staticmethod
    def detail(log_id):
        row = get_db().query_one(
            "SELECT l.*, p.prediction_id, p.model_id, p.model_name, p.model_version, p.prediction_result, "
            "p.confidence_score, p.malicious_probability, a.alert_id, a.alert_type, a.threat_level, a.alert_message, "
            "a.status AS alert_status FROM network_logs l JOIN predictions p ON p.log_id=l.log_id "
            "LEFT JOIN alerts a ON a.prediction_id=p.prediction_id WHERE l.log_id=%s", (log_id,))
        return _ser(row)

    @staticmethod
    def protocols():
        return [r["protocol"] for r in get_db().query_all(
            "SELECT DISTINCT protocol FROM network_logs WHERE protocol IS NOT NULL ORDER BY protocol")]


class Alerts:
    SELECT = (
        "SELECT a.alert_id, a.prediction_id, a.alert_type, a.threat_level, a.alert_message, a.status, a.created_at, "
        "a.updated_at, l.log_id, l.source_ip, l.destination_ip, l.protocol, l.packet_size, p.model_name, "
        "p.model_version, p.confidence_score, p.prediction_result FROM alerts a "
        "JOIN predictions p ON p.prediction_id=a.prediction_id JOIN network_logs l ON l.log_id=p.log_id")

    @staticmethod
    def _filters(f):
        where, p = [], []
        if f.get("q"):
            like = f"%{f['q']}%"
            where.append("(l.source_ip LIKE %s OR l.destination_ip LIKE %s OR a.alert_message LIKE %s OR l.protocol LIKE %s)")
            p += [like] * 4
        if f.get("threat_level"):
            where.append("a.threat_level=%s")
            p.append(f["threat_level"])
        if f.get("status"):
            where.append("a.status=%s")
            p.append(f["status"])
        if f.get("date_from"):
            where.append("a.created_at >= %s")
            p.append(day_start(f["date_from"]))
        if f.get("date_to"):
            where.append("a.created_at <= %s")
            p.append(day_end(f["date_to"]))
        if f.get("model"):
            where.append("p.model_name=%s")
            p.append(f["model"])
        return (" WHERE " + " AND ".join(where)) if where else "", p

    @staticmethod
    def list(filters, page=1, per_page=25):
        page, per_page, offset = page_args(page, per_page)
        where, p = Alerts._filters(filters)
        total = get_db().query_one(
            "SELECT COUNT(*) AS n FROM alerts a JOIN predictions p ON p.prediction_id=a.prediction_id "
            "JOIN network_logs l ON l.log_id=p.log_id" + where, p)["n"]
        rows = get_db().query_all(f"{Alerts.SELECT}{where} ORDER BY a.alert_id DESC LIMIT %s OFFSET %s",
                                  p + [per_page, offset])
        return {"items": _many(rows), "total": total, "page": page, "per_page": per_page}

    @staticmethod
    def get(alert_id):
        return _ser(get_db().query_one(Alerts.SELECT + " WHERE a.alert_id=%s", (alert_id,)))

    @staticmethod
    def related(source_ip, exclude_log_id, limit=10):
        return _many(get_db().query_all(
            f"{TRAFFIC_SELECT} WHERE l.source_ip=%s AND l.log_id<>%s ORDER BY l.log_id DESC LIMIT %s",
            (source_ip, exclude_log_id, limit)))

    @staticmethod
    def set_status(alert_id, status, user_id):
        _, n = get_db().execute("UPDATE alerts SET status=%s, updated_by=%s, updated_at=%s WHERE alert_id=%s",
                                (status, user_id, utcnow(), alert_id))
        return n

    @staticmethod
    def recent(limit=8):
        return _many(get_db().query_all(f"{Alerts.SELECT} ORDER BY a.alert_id DESC LIMIT %s", (limit,)))


# ============================================================ settings
class Settings:
    @staticmethod
    def all():
        return {r["setting_key"]: r["setting_value"] for r in
                get_db().query_all("SELECT setting_key, setting_value FROM app_settings")}

    @staticmethod
    def set(key, value):
        with get_db().transaction() as tx:
            _, n = tx.execute("UPDATE app_settings SET setting_value=%s, updated_at=%s WHERE setting_key=%s",
                              (str(value), utcnow(), key))
            if not n and not tx.query_one("SELECT 1 AS x FROM app_settings WHERE setting_key=%s", (key,)):
                tx.execute("INSERT INTO app_settings (setting_key, setting_value, updated_at) VALUES (%s,%s,%s)",
                           (key, str(value), utcnow()))


# ============================================================ statistics
class Stats:
    @staticmethod
    def totals():
        db = get_db()
        row = db.query_one(
            "SELECT COUNT(*) AS total, "
            "COALESCE(SUM(CASE WHEN prediction_result='Normal' THEN 1 ELSE 0 END),0) AS normal, "
            "COALESCE(SUM(CASE WHEN prediction_result='Malicious' THEN 1 ELSE 0 END),0) AS malicious FROM predictions")
        active = db.query_one("SELECT COUNT(*) AS n FROM alerts WHERE status='Open'")["n"]
        return {"total": int(row["total"]), "normal": int(row["normal"]), "malicious": int(row["malicious"]),
                "active_alerts": int(active)}

    @staticmethod
    def protocol_distribution(date_from=None, date_to=None):
        where, p = [], []
        if date_from:
            where.append("l.timestamp >= %s")
            p.append(day_start(date_from))
        if date_to:
            where.append("l.timestamp <= %s")
            p.append(day_end(date_to))
        w = (" WHERE " + " AND ".join(where)) if where else ""
        return get_db().query_all(
            "SELECT COALESCE(l.protocol,'UNKNOWN') AS protocol, COUNT(*) AS total, "
            "SUM(CASE WHEN p.prediction_result='Malicious' THEN 1 ELSE 0 END) AS malicious "
            f"FROM network_logs l JOIN predictions p ON p.log_id=l.log_id{w} GROUP BY l.protocol ORDER BY total DESC", p)

    @staticmethod
    def alert_breakdown(date_from=None, date_to=None):
        where, p = [], []
        if date_from:
            where.append("created_at >= %s")
            p.append(day_start(date_from))
        if date_to:
            where.append("created_at <= %s")
            p.append(day_end(date_to))
        w = (" WHERE " + " AND ".join(where)) if where else ""
        by_level = get_db().query_all(f"SELECT threat_level, COUNT(*) AS n FROM alerts{w} GROUP BY threat_level", p)
        by_status = get_db().query_all(f"SELECT status, COUNT(*) AS n FROM alerts{w} GROUP BY status", p)
        by_type = get_db().query_all(f"SELECT alert_type, COUNT(*) AS n FROM alerts{w} GROUP BY alert_type", p)
        return {"by_level": {r["threat_level"]: r["n"] for r in by_level},
                "by_status": {r["status"]: r["n"] for r in by_status},
                "by_type": {r["alert_type"]: r["n"] for r in by_type}}

    @staticmethod
    def timeline(minutes=30, bucket_seconds=60, date_from=None, date_to=None):
        """Bucketed counts. Grouping is done in Python so the SQL stays portable across MySQL/SQLite."""
        if date_from or date_to:
            where, p = [], []
            if date_from:
                where.append("l.timestamp >= %s")
                p.append(day_start(date_from))
            if date_to:
                where.append("l.timestamp <= %s")
                p.append(day_end(date_to))
            rows = get_db().query_all(
                "SELECT l.timestamp, p.prediction_result FROM network_logs l JOIN predictions p ON p.log_id=l.log_id "
                "WHERE " + " AND ".join(where) + " ORDER BY l.timestamp DESC LIMIT 50000", p)
        else:
            since = utcnow() - timedelta(minutes=minutes)
            rows = get_db().query_all(
                "SELECT l.timestamp, p.prediction_result FROM network_logs l JOIN predictions p ON p.log_id=l.log_id "
                "WHERE l.timestamp >= %s ORDER BY l.timestamp DESC LIMIT 50000", (since,))
        buckets = {}
        for r in rows:
            ts = r["timestamp"]
            if isinstance(ts, str):
                ts = datetime.strptime(ts[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
            key = int(ts.replace(tzinfo=timezone.utc).timestamp() // bucket_seconds * bucket_seconds)
            b = buckets.setdefault(key, {"normal": 0, "malicious": 0})
            b["malicious" if r["prediction_result"] == "Malicious" else "normal"] += 1
        return [{"t": datetime.fromtimestamp(k, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), **v}
                for k, v in sorted(buckets.items())]
