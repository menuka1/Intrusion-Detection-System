"""Generate SYNTHETIC sample datasets that mimic the column structure of NSL-KDD and UNSW-NB15.

These are NOT the real benchmark datasets. They exist so that the application, the tests and
demonstrations work offline. Results on them say nothing about real-world detection quality.
Use the genuine NSL-KDD (KDDTrain+.txt / KDDTest+.txt) and UNSW-NB15 training/testing CSVs for
actual evaluation (see README).

    python scripts/generate_sample_data.py [rows]
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from preprocessing.dataset_loader import NSL_KDD_COLUMNS, UNSW_COLUMNS  # noqa: E402

OUT = ROOT / "datasets" / "sample"


def _pick(rng, choices, p, n):
    return rng.choice(choices, size=n, p=p)


def nsl_kdd(n, seed=7):
    rng = np.random.default_rng(seed)
    kinds = rng.choice(["normal", "neptune", "smurf", "satan", "portsweep", "guess_passwd", "buffer_overflow"],
                       size=n, p=[0.53, 0.20, 0.08, 0.07, 0.05, 0.05, 0.02])
    rows = []
    for k in kinds:
        stealth = rng.random() < 0.06  # some attacks look almost normal -> imperfect classifiers
        r = dict.fromkeys(NSL_KDD_COLUMNS[:41], 0)
        if k == "normal" or stealth:
            r.update(protocol_type=_pick(rng, ["tcp", "udp", "icmp"], [.8, .15, .05], 1)[0],
                     service=_pick(rng, ["http", "smtp", "ftp_data", "domain_u", "private", "other"], [.4, .15, .1, .15, .1, .1], 1)[0],
                     flag=_pick(rng, ["SF", "S0", "REJ"], [.93, .03, .04], 1)[0],
                     duration=int(rng.exponential(30)), src_bytes=int(rng.lognormal(5.5, 1.2)),
                     dst_bytes=int(rng.lognormal(7, 1.5)), logged_in=int(rng.random() < .7),
                     count=int(rng.integers(1, 30)), srv_count=int(rng.integers(1, 30)),
                     serror_rate=round(rng.random() * .05, 2), rerror_rate=round(rng.random() * .05, 2),
                     same_srv_rate=round(.85 + rng.random() * .15, 2), diff_srv_rate=round(rng.random() * .1, 2),
                     dst_host_count=int(rng.integers(20, 255)), dst_host_srv_count=int(rng.integers(20, 255)),
                     dst_host_same_srv_rate=round(.7 + rng.random() * .3, 2), dst_host_serror_rate=round(rng.random() * .05, 2))
        elif k == "neptune":
            r.update(protocol_type="tcp", service=_pick(rng, ["private", "http", "telnet"], [.7, .2, .1], 1)[0], flag=_pick(rng, ["S0", "REJ"], [.9, .1], 1)[0],
                     count=int(rng.integers(120, 511)), srv_count=int(rng.integers(5, 30)), serror_rate=round(.9 + rng.random() * .1, 2),
                     srv_serror_rate=1.0, same_srv_rate=round(rng.random() * .15, 2), diff_srv_rate=round(.05 + rng.random() * .1, 2),
                     dst_host_count=255, dst_host_srv_count=int(rng.integers(1, 25)), dst_host_serror_rate=1.0, dst_host_srv_serror_rate=1.0)
        elif k == "smurf":
            r.update(protocol_type="icmp", service="ecr_i", flag="SF", src_bytes=int(_pick(rng, [520, 1032], [.2, .8], 1)[0]),
                     count=int(rng.integers(200, 511)), srv_count=int(rng.integers(200, 511)), same_srv_rate=1.0,
                     dst_host_count=255, dst_host_srv_count=255, dst_host_same_srv_rate=1.0)
        elif k in ("satan", "portsweep"):
            r.update(protocol_type="tcp", service=_pick(rng, ["private", "other", "ftp", "telnet"], [.4, .3, .15, .15], 1)[0],
                     flag=_pick(rng, ["REJ", "RSTR", "S0"], [.5, .3, .2], 1)[0], count=int(rng.integers(1, 15)),
                     srv_count=int(rng.integers(1, 5)), rerror_rate=round(.5 + rng.random() * .5, 2),
                     srv_rerror_rate=round(.5 + rng.random() * .5, 2), same_srv_rate=round(rng.random() * .3, 2),
                     diff_srv_rate=round(.4 + rng.random() * .6, 2), dst_host_count=int(rng.integers(100, 255)),
                     dst_host_srv_count=int(rng.integers(1, 15)), dst_host_diff_srv_rate=round(.4 + rng.random() * .6, 2),
                     dst_host_rerror_rate=round(.4 + rng.random() * .6, 2))
        elif k == "guess_passwd":
            r.update(protocol_type="tcp", service=_pick(rng, ["telnet", "ftp", "pop_3"], [.5, .3, .2], 1)[0], flag="SF",
                     duration=int(rng.integers(0, 10)), src_bytes=int(rng.integers(100, 140)), dst_bytes=int(rng.integers(100, 300)),
                     num_failed_logins=int(rng.integers(1, 6)), count=int(rng.integers(1, 5)), srv_count=int(rng.integers(1, 5)),
                     same_srv_rate=1.0, dst_host_count=int(rng.integers(1, 40)), dst_host_srv_count=int(rng.integers(1, 40)))
        else:  # buffer_overflow
            r.update(protocol_type="tcp", service=_pick(rng, ["telnet", "ftp_data"], [.7, .3], 1)[0], flag="SF",
                     duration=int(rng.integers(5, 300)), src_bytes=int(rng.integers(800, 3000)), dst_bytes=int(rng.integers(1000, 6000)),
                     logged_in=1, hot=int(rng.integers(1, 6)), num_compromised=int(rng.integers(1, 4)), root_shell=1,
                     num_root=int(rng.integers(1, 5)), num_file_creations=int(rng.integers(0, 3)), count=1, srv_count=1,
                     same_srv_rate=1.0, dst_host_count=int(rng.integers(1, 10)), dst_host_srv_count=int(rng.integers(1, 10)))
        r["label"] = k
        r["difficulty"] = int(rng.integers(5, 22))
        rows.append(r)
    df = pd.DataFrame(rows, columns=NSL_KDD_COLUMNS)
    dup = df.sample(frac=0.01, random_state=seed)
    return pd.concat([df, dup], ignore_index=True)


def unsw(n, seed=11):
    rng = np.random.default_rng(seed)
    cats = rng.choice(["Normal", "Generic", "Exploits", "Fuzzers", "DoS", "Reconnaissance"], size=n,
                      p=[0.50, 0.17, 0.14, 0.09, 0.05, 0.05])
    rows = []
    for i, c in enumerate(cats):
        mal = c != "Normal" and rng.random() > 0.05
        r = dict.fromkeys(UNSW_COLUMNS, 0)
        if not mal:
            r.update(proto=_pick(rng, ["tcp", "udp", "arp"], [.6, .35, .05], 1)[0], service=_pick(rng, ["-", "http", "dns", "ftp", "smtp"], [.3, .3, .25, .08, .07], 1)[0],
                     state=_pick(rng, ["FIN", "CON", "INT"], [.6, .25, .15], 1)[0], dur=float(rng.exponential(0.5)),
                     spkts=int(rng.integers(2, 40)), dpkts=int(rng.integers(0, 40)), sbytes=int(rng.lognormal(6.5, 1)),
                     dbytes=int(rng.lognormal(7.5, 1.3)), rate=float(rng.lognormal(5, 1.5)), sttl=int(_pick(rng, [62, 254, 31], [.5, .3, .2], 1)[0]),
                     dttl=int(_pick(rng, [252, 60, 29], [.5, .3, .2], 1)[0]), sload=float(rng.lognormal(10, 1.5)), dload=float(rng.lognormal(10.5, 1.5)),
                     ct_srv_src=int(rng.integers(1, 12)), ct_dst_ltm=int(rng.integers(1, 10)), ct_state_ttl=int(_pick(rng, [0, 1, 2], [.5, .3, .2], 1)[0]),
                     smean=int(rng.integers(50, 400)), dmean=int(rng.integers(50, 900)), swin=255, dwin=255)
        else:
            r.update(proto=_pick(rng, ["tcp", "udp", "unas", "ospf"], [.55, .3, .1, .05], 1)[0], service=_pick(rng, ["-", "http", "dns", "ftp"], [.55, .2, .15, .1], 1)[0],
                     state=_pick(rng, ["INT", "FIN", "CON", "REQ"], [.45, .2, .2, .15], 1)[0], dur=float(rng.exponential(0.08)),
                     spkts=int(rng.integers(1, 12)), dpkts=int(rng.integers(0, 6)), sbytes=int(rng.lognormal(5.0, 1.0)),
                     dbytes=int(rng.lognormal(4.0, 1.5)), rate=float(rng.lognormal(8, 1.5)), sttl=int(_pick(rng, [254, 31, 62], [.6, .25, .15], 1)[0]),
                     dttl=int(_pick(rng, [0, 252, 29], [.5, .3, .2], 1)[0]), sload=float(rng.lognormal(13, 1.5)), dload=float(rng.lognormal(8, 2)),
                     ct_srv_src=int(rng.integers(5, 40)), ct_dst_ltm=int(rng.integers(5, 30)), ct_state_ttl=int(_pick(rng, [0, 1, 2], [.2, .3, .5], 1)[0]),
                     smean=int(rng.integers(20, 200)), dmean=int(rng.integers(0, 200)), swin=int(_pick(rng, [255, 0], [.7, .3], 1)[0]), dwin=int(_pick(rng, [255, 0], [.5, .5], 1)[0]))
        r["id"] = i + 1
        r["attack_cat"] = c if mal else "Normal"
        r["label"] = 1 if mal else 0
        rows.append(r)
    return pd.DataFrame(rows, columns=UNSW_COLUMNS)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 6000
    OUT.mkdir(parents=True, exist_ok=True)
    nsl_kdd(n).to_csv(OUT / "nslkdd_synthetic_sample.csv", header=False, index=False)  # official files have no header
    unsw(n).to_csv(OUT / "unsw_nb15_synthetic_sample.csv", index=False)
    print(f"Wrote synthetic samples ({n} rows each) to {OUT}")
