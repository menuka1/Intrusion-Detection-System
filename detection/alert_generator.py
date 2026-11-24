"""Alert generation and *severity assessment*.

Severity is deliberately independent of model confidence. Confidence says how
sure the model is that traffic is malicious; severity is a transparent
rule-based estimate of operational impact:

  1. A malicious detection starts at MEDIUM.
  2. Isolated and small (packet_size < severity_small_size)            -> LOW.
  3. Large transfer (packet_size >= severity_size_threshold)           -> +1 level.
  4. Repetition: >= severity_burst_count malicious detections from the
     same source within 60 s                                           -> +1 level
     (>= 3x that count                                                 -> +2 levels).
  Levels are capped at CRITICAL.

The binary classifier does not know the attack family, so the rules use only
volume and repetition. They are heuristics for triage, not an attack taxonomy.
"""
import time
from collections import defaultdict, deque

LEVELS = ["Low", "Medium", "High", "Critical"]

DEFAULT_SETTINGS = {
    "default_dataset_id": "",
    "replay_speed": "5",
    "alert_min_confidence": "0.5",
    "severity_size_threshold": "100000",
    "severity_small_size": "1000",
    "severity_burst_count": "5",
    "dashboard_refresh_seconds": "5",
}


def setting_float(settings, key):
    try:
        return float(settings.get(key, DEFAULT_SETTINGS[key]))
    except (TypeError, ValueError):
        return float(DEFAULT_SETTINGS[key])


class BurstTracker:
    """Counts recent malicious detections per source (sliding 60 s window, in memory)."""

    def __init__(self, window=60.0):
        self.window = window
        self._hits = defaultdict(deque)

    def hit(self, source, now=None):
        now = time.monotonic() if now is None else now
        q = self._hits[source]
        q.append(now)
        while q and now - q[0] > self.window:
            q.popleft()
        if len(self._hits) > 5000:  # bound memory
            for k in [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]:
                del self._hits[k]
        return len(q)


def assess_severity(packet_size, recent_from_source, settings):
    """Return (level, reasons[]) using the documented rules."""
    size = packet_size or 0
    big = setting_float(settings, "severity_size_threshold")
    small = setting_float(settings, "severity_small_size")
    burst = max(1, int(setting_float(settings, "severity_burst_count")))
    idx, reasons = 1, []
    if recent_from_source >= 3 * burst:
        idx += 2
        reasons.append(f"{recent_from_source} detections from this source in 60 s")
    elif recent_from_source >= burst:
        idx += 1
        reasons.append(f"{recent_from_source} detections from this source in 60 s")
    if size >= big:
        idx += 1
        reasons.append(f"large transfer ({size} bytes)")
    if not reasons and size < small:
        idx = 0
        reasons.append(f"isolated, small flow ({size} bytes)")
    if not reasons:
        reasons.append("isolated malicious detection")
    return LEVELS[min(idx, len(LEVELS) - 1)], reasons


def build_alert(log_fields, model_name, confidence, level, reasons):
    return {
        "alert_type": "Suspicious Traffic (ML)",
        "threat_level": level,
        "alert_message": (f"Malicious traffic from {log_fields['source_ip']} to {log_fields['destination_ip']} "
                          f"[{log_fields['protocol']}] flagged by {model_name} "
                          f"(confidence {confidence:.1%}). Severity basis: {'; '.join(reasons)}.")[:500],
    }
