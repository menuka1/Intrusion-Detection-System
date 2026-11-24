"""Dataset profiles, loading and validation for NSL-KDD, UNSW-NB15 and custom CSV files.

NSL-KDD and UNSW-NB15 have different feature structures, so each has its own
profile. A profile says which column is the label, which columns must never be
used as features (identifiers / leakage), and which columns describe the
protocol, size and endpoints for the monitoring views.
"""
import csv
import io
import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

NSL_KDD_FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
NSL_KDD_COLUMNS = NSL_KDD_FEATURES + ["label", "difficulty"]

UNSW_COLUMNS = [
    "id", "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean",
    "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports", "attack_cat", "label",
]

NORMAL_LABELS = {"normal", "benign", "0", "0.0", "false", "legitimate", "clean", "no", "good", "none"}
LABEL_CANDIDATES = ["label", "class", "target", "attack", "attack_cat", "outcome", "result", "is_attack", "malicious"]
PROTOCOL_CANDIDATES = ["protocol_type", "proto", "protocol", "protocol_name"]
SRC_IP_CANDIDATES = ["srcip", "src_ip", "source_ip", "source ip", "src ip", "id.orig_h"]
DST_IP_CANDIDATES = ["dstip", "dst_ip", "destination_ip", "destination ip", "dst ip", "id.resp_h"]
SIZE_CANDIDATES = ["packet_size", "bytes", "total_bytes", "flow_bytes", "length", "pkt_len"]


@dataclass
class DatasetProfile:
    key: str
    title: str
    label_column: str | None
    exclude_columns: list = field(default_factory=list)  # never used as features
    size_columns: list = field(default_factory=list)      # summed -> packet_size
    protocol_column: str | None = None
    src_ip_column: str | None = None
    dst_ip_column: str | None = None


PROFILES = {
    "nsl-kdd": DatasetProfile(
        "nsl-kdd", "NSL-KDD", "label", exclude_columns=["difficulty"],
        size_columns=["src_bytes", "dst_bytes"], protocol_column="protocol_type"),
    "unsw-nb15": DatasetProfile(
        "unsw-nb15", "UNSW-NB15", "label", exclude_columns=["id", "attack_cat"],
        size_columns=["sbytes", "dbytes"], protocol_column="proto"),
    "custom": DatasetProfile("custom", "Custom CSV", None),
}


class DatasetError(ValueError):
    """User-facing dataset validation error."""


def _first_present(columns, candidates):
    lowered = {str(c).strip().lower(): c for c in columns}
    for cand in candidates:
        if cand in lowered:
            return lowered[cand]
    return None


def get_profile(dataset_type, columns=None):
    """Return the profile, specialised for ``custom`` datasets using the actual columns."""
    base = PROFILES.get(dataset_type)
    if base is None:
        raise DatasetError(f"Unknown dataset type '{dataset_type}'.")
    if dataset_type != "custom" or columns is None:
        return base
    return DatasetProfile(
        "custom", "Custom CSV", _first_present(columns, LABEL_CANDIDATES),
        size_columns=[c for c in [_first_present(columns, SIZE_CANDIDATES)] if c],
        protocol_column=_first_present(columns, PROTOCOL_CANDIDATES),
        src_ip_column=_first_present(columns, SRC_IP_CANDIDATES),
        dst_ip_column=_first_present(columns, DST_IP_CANDIDATES))


def with_endpoint_columns(profile, columns):
    """Add IP columns (if present) to any profile, e.g. raw UNSW files with srcip/dstip."""
    profile.src_ip_column = profile.src_ip_column or _first_present(columns, SRC_IP_CANDIDATES)
    profile.dst_ip_column = profile.dst_ip_column or _first_present(columns, DST_IP_CANDIDATES)
    return profile


# ---------------------------------------------------------------- reading
def sniff_text(path, nbytes=8192):
    """Reject binary files: uploaded datasets must be plain text and are never executed."""
    with open(path, "rb") as fh:
        head = fh.read(nbytes)
    if not head.strip():
        raise DatasetError("The uploaded file is empty.")
    if b"\x00" in head:
        raise DatasetError("The file is not a text/CSV file (binary content detected).")
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        try:
            head.decode("latin-1")
        except UnicodeDecodeError as exc:
            raise DatasetError("Unsupported file encoding.") from exc
    return head.decode("utf-8", errors="replace")


def _looks_headerless_nsl(first_line):
    parts = [p.strip().strip('"') for p in first_line.split(",")]
    return len(parts) in (42, 43) and parts[1].lower() in {"tcp", "udp", "icmp"}


def detect_dataset_type(path):
    """Best-effort type detection from the header / first row."""
    first = sniff_text(path).splitlines()[0]
    if _looks_headerless_nsl(first):
        return "nsl-kdd"
    cols = {c.strip().strip('"').lower() for c in first.split(",")}
    if {"protocol_type", "src_bytes", "dst_bytes", "service", "flag"} <= cols:
        return "nsl-kdd"
    if {"proto", "sbytes", "dbytes", "spkts", "dpkts"} <= cols:
        return "unsw-nb15"
    return "custom"


def read_dataset(path, dataset_type, nrows=None):
    """Load a dataset into a DataFrame with a header, according to its type."""
    path = Path(path)
    sniff_text(path)
    first_line = path.open("r", encoding="utf-8", errors="replace").readline()
    try:
        if dataset_type == "nsl-kdd" and _looks_headerless_nsl(first_line):
            n = len(first_line.split(","))
            names = NSL_KDD_COLUMNS if n == 43 else NSL_KDD_COLUMNS[:42]
            df = pd.read_csv(path, header=None, names=names, nrows=nrows, skipinitialspace=True,
                             encoding_errors="replace")
        else:
            df = pd.read_csv(path, nrows=nrows, skipinitialspace=True, encoding_errors="replace")
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError, csv.Error) as exc:
        raise DatasetError(f"The file could not be parsed as CSV: {exc}") from exc
    df.columns = [str(c).strip() for c in df.columns]
    return df


def validate_dataset(df, dataset_type, label_column=None):
    """Raise DatasetError for structurally unusable datasets; return (label_column, warnings)."""
    warnings = []
    if df.shape[0] < 20:
        raise DatasetError("The dataset needs at least 20 records.")
    if df.shape[1] < 3:
        raise DatasetError("The dataset needs at least 3 columns (features + label).")
    cols = list(df.columns)
    if len(set(cols)) != len(cols):
        raise DatasetError("Duplicate column names were found in the header.")
    if any(re.fullmatch(r"Unnamed: \d+", c) for c in cols):
        warnings.append("Some columns have no name (Unnamed); consider fixing the header.")
    profile = get_profile(dataset_type, cols)
    if dataset_type in ("nsl-kdd", "unsw-nb15"):
        expected = NSL_KDD_FEATURES if dataset_type == "nsl-kdd" else [c for c in UNSW_COLUMNS if c not in ("id", "attack_cat", "label")]
        missing = [c for c in expected if c not in cols]
        if missing:
            raise DatasetError(
                f"This file does not match the {profile.title} structure; missing columns: "
                + ", ".join(missing[:8]) + ("..." if len(missing) > 8 else ""))
    label = label_column or profile.label_column
    if label and label not in cols:
        if dataset_type == "custom":
            raise DatasetError(f"Label column '{label}' was not found in the dataset.")
        raise DatasetError(f"The {profile.title} label column '{label}' is missing.")
    if dataset_type != "custom" and not label:
        raise DatasetError("No label column was found.")
    if label is None:
        warnings.append("No label column detected: choose one during preprocessing before training.")
    return label, warnings


# ---------------------------------------------------------------- labels
def binarize_labels(series):
    """Map any label column to 0 (normal) / 1 (malicious). Missing labels become NaN."""
    def conv(v):
        if pd.isna(v):
            return np.nan
        s = str(v).strip().lower()
        if s.endswith(".0"):
            s = s[:-2]
        return 0.0 if s in NORMAL_LABELS else 1.0
    return series.map(conv)


def unique_label_values(series, limit=15):
    vc = series.astype(str).value_counts().head(limit)
    return {str(k): int(v) for k, v in vc.items()}


# ---------------------------------------------------------------- endpoints
def simulated_ip(index, kind):
    """Deterministic private-range address used when the dataset has no IP columns."""
    rng = np.random.default_rng(int(index) * 2 + (0 if kind == "src" else 1))
    pool = int(rng.integers(1, 41))
    host = int(rng.integers(2, 250))
    return f"10.0.{pool}.{host}" if kind == "src" else f"192.168.{int(rng.integers(0, 4))}.{int(rng.integers(2, 60))}"


def extract_log_fields(record, profile, index=0):
    """Return source_ip, destination_ip, protocol, packet_size, simulated(bool) for a feature record."""
    simulated = False
    src = str(record.get(profile.src_ip_column)) if profile.src_ip_column and record.get(profile.src_ip_column) not in (None, "") else None
    dst = str(record.get(profile.dst_ip_column)) if profile.dst_ip_column and record.get(profile.dst_ip_column) not in (None, "") else None
    if src is None:
        src, simulated = simulated_ip(index, "src"), True
    if dst is None:
        dst, simulated = simulated_ip(index, "dst"), True
    proto = record.get(profile.protocol_column) if profile.protocol_column else None
    proto = str(proto).upper() if proto not in (None, "") and not (isinstance(proto, float) and np.isnan(proto)) else "UNKNOWN"
    size = 0
    for col in profile.size_columns:
        try:
            v = float(record.get(col) or 0)
            size += int(v) if np.isfinite(v) else 0
        except (TypeError, ValueError):
            pass
    return {"source_ip": src[:45], "destination_ip": dst[:45], "protocol": proto[:20],
            "packet_size": size, "simulated_endpoints": simulated}


def df_to_clean_json_records(df):
    """Convert to JSON-safe python records (NaN -> None)."""
    return df.astype(object).where(df.notna(), None).to_dict(orient="records")
