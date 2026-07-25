"""
Synthetic cybersecurity access-log generator for SentinelDNA.

Generates realistic, profile-consistent behavioral data for 300+ identities
with ~98-99% normal events and ~1-2% injected anomalies.
"""

import json
import random
import uuid
import numpy as np
from datetime import datetime, timedelta
from typing import Any

# ─── Seed for reproducibility ────────────────────────────────────────────────
RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

# ─── Configuration ────────────────────────────────────────────────────────────
NUM_IDENTITIES = 300
TARGET_EVENTS = 52000
ANOMALY_RATE = 0.015          # 1.5% anomalous events
NUM_USERS = 210
NUM_SERVICE_ACCOUNTS = 55
NUM_EDGE_DEVICES = 35

# Date window: last 90 days
END_DATE = datetime(2026, 7, 25)
START_DATE = END_DATE - timedelta(days=90)

# ─── Geographic locations (city, lat, lng) ────────────────────────────────────
LOCATIONS = [
    {"city": "New York",       "lat": 40.7128,  "lng": -74.0060},
    {"city": "San Francisco",  "lat": 37.7749,  "lng": -122.4194},
    {"city": "Chicago",        "lat": 41.8781,  "lng": -87.6298},
    {"city": "Austin",         "lat": 30.2672,  "lng": -97.7431},
    {"city": "Seattle",        "lat": 47.6062,  "lng": -122.3321},
    {"city": "Boston",         "lat": 42.3601,  "lng": -71.0589},
    {"city": "Denver",         "lat": 39.7392,  "lng": -104.9903},
    {"city": "Atlanta",        "lat": 33.7490,  "lng": -84.3880},
    {"city": "Dallas",         "lat": 32.7767,  "lng": -96.7970},
    {"city": "Los Angeles",    "lat": 34.0522,  "lng": -118.2437},
    # Far locations for impossible_travel injection
    {"city": "London",         "lat": 51.5074,  "lng": -0.1278},
    {"city": "Tokyo",          "lat": 35.6762,  "lng": 139.6503},
    {"city": "Sydney",         "lat": -33.8688, "lng": 151.2093},
    {"city": "Singapore",      "lat": 1.3521,   "lng": 103.8198},
    {"city": "Dubai",          "lat": 25.2048,  "lng": 55.2708},
]
DOMESTIC_LOCATIONS = LOCATIONS[:10]
FOREIGN_LOCATIONS  = LOCATIONS[10:]

DEPARTMENTS = ["Engineering", "Finance", "HR", "Sales", "Operations", "IT"]

RESOURCES_BY_DEPT = {
    "Engineering": [
        "/code/repos", "/ci/builds", "/monitoring/metrics", "/api/internal",
        "/docker/registry", "/wiki/tech-docs", "/jira/tickets", "/grafana/dashboards",
        "/k8s/deployments", "/logs/application",
    ],
    "Finance": [
        "/finance/reports", "/erp/invoices", "/payroll/records", "/audit/logs",
        "/budget/forecasts", "/accounts/payable", "/accounts/receivable",
        "/compliance/sox", "/banking/portal", "/expenses/approvals",
    ],
    "HR": [
        "/hr/records", "/hr/onboarding", "/benefits/portal", "/recruitment/ats",
        "/performance/reviews", "/training/lms", "/policy/documents",
        "/payroll/hr-view", "/org/charts", "/survey/results",
    ],
    "Sales": [
        "/crm/contacts", "/crm/opportunities", "/sales/pipeline", "/quotes/generator",
        "/contracts/portal", "/marketing/campaigns", "/analytics/sales",
        "/customer/success", "/demo/environments", "/proposals/templates",
    ],
    "Operations": [
        "/ops/runbooks", "/ops/alerts", "/inventory/management", "/vendor/portal",
        "/fleet/tracking", "/facilities/mgmt", "/supply/chain", "/ops/reports",
        "/maintenance/tickets", "/ops/dashboard",
    ],
    "IT": [
        "/it/helpdesk", "/it/assets", "/network/configs", "/security/policies",
        "/ad/users", "/ad/groups", "/patch/management", "/backup/status",
        "/firewall/rules", "/vpn/gateway", "/certificates/mgmt",
    ],
    "service_account": [
        "/api/data-sync", "/api/batch-jobs", "/api/reports", "/api/webhooks",
        "/db/read-replica", "/storage/backup", "/messaging/queue",
        "/monitoring/health", "/cache/invalidate", "/api/export",
    ],
    "edge_device": [
        "/telemetry/sensors", "/iot/gateway", "/edge/config", "/firmware/updates",
        "/telemetry/metrics", "/device/register", "/ota/packages", "/edge/logs",
        "/device/diagnostics", "/network/edge",
    ],
}

AUTH_METHODS = {
    "user":            ["mfa", "sso", "password", "biometric"],
    "service_account": ["api_key", "certificate", "sso"],
    "edge_device":     ["certificate", "api_key"],
}

COMMAND_SEQUENCES = {
    "Engineering":     [["git pull", "make build"], ["kubectl get pods"], ["ssh bastion", "tail -f app.log"], ["docker ps", "docker logs"], ["curl -s api"]],
    "Finance":         [["query report"], ["export csv"], ["open dashboard"], ["approve invoice"], ["review audit"]],
    "HR":              [["open employee record"], ["update profile"], ["run payroll"], ["send offer letter"], ["review application"]],
    "Sales":           [["open crm"], ["update opportunity"], ["generate quote"], ["send proposal"], ["log call"]],
    "Operations":      [["check alert"], ["run playbook"], ["update ticket"], ["review inventory"], ["submit order"]],
    "IT":              [["query ad"], ["reset password"], ["deploy patch"], ["review firewall"], ["check backup"]],
    "service_account": [["batch_sync --full"], ["batch_sync --delta"], ["export_report --format=csv"], ["health_check"], ["index_rebuild"]],
    "edge_device":     [["send_telemetry"], ["heartbeat"], ["ota_check"], ["upload_metrics"], ["register_device"]],
}

# ─── IP address helpers ───────────────────────────────────────────────────────

def random_ip(prefix: str = "") -> str:
    if prefix:
        parts = prefix.split(".")
        parts += [str(random.randint(1, 254)) for _ in range(4 - len(parts))]
        return ".".join(parts)
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def random_device_fingerprint() -> str:
    return "dev-" + uuid.uuid4().hex[:12]


# ─── Identity builder ─────────────────────────────────────────────────────────

def build_identity(idx: int, entity_type: str, department: str | None) -> dict[str, Any]:
    """Create an identity with a hidden normal behavioral profile."""
    if entity_type == "user":
        entity_id = f"USER_{idx:03d}"
    elif entity_type == "service_account":
        entity_id = f"SVC_{idx:03d}"
    else:
        entity_id = f"EDGE_{idx:03d}"

    # Primary location (weighted toward domestic)
    primary_loc = random.choice(DOMESTIC_LOCATIONS)

    # Normal working hours (realistic per type)
    if entity_type == "user":
        hour_start = random.randint(7, 10)
        work_hours = list(range(hour_start, hour_start + random.randint(8, 10)))
    elif entity_type == "service_account":
        # Services run at consistent times, often overnight
        hour_start = random.randint(0, 23)
        work_hours = [hour_start, (hour_start + 1) % 24, (hour_start + 2) % 24]
    else:
        # Edge devices run continuously but with maintenance windows
        work_hours = list(range(0, 24))

    # Known devices (1-3 trusted devices)
    num_devices = random.randint(1, 3) if entity_type == "user" else 1
    known_devices = [random_device_fingerprint() for _ in range(num_devices)]

    # Resources
    dept_key = department if department else entity_type
    resources = random.sample(RESOURCES_BY_DEPT.get(dept_key, RESOURCES_BY_DEPT["IT"]), k=min(5, len(RESOURCES_BY_DEPT.get(dept_key, RESOURCES_BY_DEPT["IT"]))))

    # Auth method preference
    type_methods = AUTH_METHODS.get(entity_type, ["password"])
    preferred_auth = random.choice(type_methods)

    # Session duration range (seconds)
    if entity_type == "user":
        dur_min = random.randint(60, 600)
        dur_max = dur_min + random.randint(600, 7200)
    elif entity_type == "service_account":
        dur_min = random.randint(5, 30)
        dur_max = dur_min + random.randint(30, 300)
    else:
        dur_min = random.randint(10, 60)
        dur_max = dur_min + random.randint(60, 600)

    # IP subnet (each identity tends to come from a consistent subnet)
    ip_prefix = f"10.{random.randint(0,255)}.{random.randint(0,255)}"

    # Typical commands
    dept_key2 = department if department else entity_type
    typical_cmds = random.sample(COMMAND_SEQUENCES.get(dept_key2, COMMAND_SEQUENCES["IT"]), k=min(3, len(COMMAND_SEQUENCES.get(dept_key2, COMMAND_SEQUENCES["IT"]))))

    profile = {
        "normal_hours":      work_hours,
        "primary_location":  primary_loc["city"],
        "primary_lat":       primary_loc["lat"],
        "primary_lng":       primary_loc["lng"],
        "known_devices":     known_devices,
        "common_resources":  resources,
        "preferred_auth":    preferred_auth,
        "session_dur_min":   dur_min,
        "session_dur_max":   dur_max,
        "ip_prefix":         ip_prefix,
        "typical_commands":  typical_cmds,
    }

    return {
        "entity_id":   entity_id,
        "entity_type": entity_type,
        "department":  department,
        "profile":     profile,
        "created_at":  START_DATE.isoformat(),
    }


# ─── Event builders ───────────────────────────────────────────────────────────

def make_normal_event(identity: dict, profile: dict) -> dict[str, Any]:
    """Generate a single normal event consistent with the identity's profile."""
    # Timestamp: pick a normal working hour on a random day in the window
    day_offset = random.randint(0, 89)
    hour = random.choice(profile["normal_hours"])
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = START_DATE + timedelta(days=day_offset, hours=hour, minutes=minute, seconds=second)

    # Location: mostly primary, occasional small drift
    if random.random() < 0.95:
        lat = profile["primary_lat"] + np.random.normal(0, 0.05)
        lng = profile["primary_lng"] + np.random.normal(0, 0.05)
        geo = profile["primary_location"]
    else:
        # Occasional travel within domestic
        alt_loc = random.choice(DOMESTIC_LOCATIONS)
        lat = alt_loc["lat"] + np.random.normal(0, 0.05)
        lng = alt_loc["lng"] + np.random.normal(0, 0.05)
        geo = alt_loc["city"]

    # Device: pick from known devices
    device = random.choice(profile["known_devices"])

    # IP: from known subnet
    source_ip = random_ip(profile["ip_prefix"])

    # Resource: from common resources
    resource = random.choice(profile["common_resources"])

    # Auth: mostly preferred, occasionally an alternative
    entity_type = identity["entity_type"]
    all_methods = AUTH_METHODS.get(entity_type, ["password"])
    if random.random() < 0.9:
        auth_method = profile["preferred_auth"]
    else:
        auth_method = random.choice(all_methods)

    auth_success = True if random.random() < 0.97 else False

    session_dur = random.uniform(profile["session_dur_min"], profile["session_dur_max"])

    cmds = random.choice(profile["typical_commands"]) if profile["typical_commands"] else ["login"]

    return {
        "event_id":           str(uuid.uuid4()),
        "entity_id":          identity["entity_id"],
        "entity_type":        entity_type,
        "timestamp":          ts.isoformat(),
        "source_ip":          source_ip,
        "geo_location":       geo,
        "latitude":           round(lat, 4),
        "longitude":          round(lng, 4),
        "resource_accessed":  resource,
        "auth_method":        auth_method,
        "auth_success":       auth_success,
        "session_duration":   round(session_dur, 1),
        "command_sequence":   json.dumps(cmds),
        "device_fingerprint": device,
        "department":         identity.get("department"),
        "label":              "normal",
    }


# ─── Anomaly injectors ────────────────────────────────────────────────────────

def inject_brute_force(identity: dict, profile: dict, base_ts: datetime) -> list[dict]:
    """Many failed auth attempts from same IP in a short window."""
    events = []
    attack_ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    loc = profile["primary_location"]
    lat, lng = profile["primary_lat"], profile["primary_lng"]
    num_attempts = random.randint(15, 40)
    for i in range(num_attempts):
        ts = base_ts + timedelta(seconds=i * random.randint(2, 10))
        events.append({
            "event_id":           str(uuid.uuid4()),
            "entity_id":          identity["entity_id"],
            "entity_type":        identity["entity_type"],
            "timestamp":          ts.isoformat(),
            "source_ip":          attack_ip,
            "geo_location":       loc,
            "latitude":           round(lat + np.random.normal(0, 0.01), 4),
            "longitude":          round(lng + np.random.normal(0, 0.01), 4),
            "resource_accessed":  "/auth/login",
            "auth_method":        "password",
            "auth_success":       False,
            "session_duration":   round(random.uniform(0.5, 3.0), 1),
            "command_sequence":   json.dumps(["login_attempt"]),
            "device_fingerprint": random_device_fingerprint(),
            "department":         identity.get("department"),
            "label":              "brute_force",
        })
    return events


def inject_impossible_travel(identity: dict, profile: dict, base_ts: datetime) -> list[dict]:
    """Same identity authenticates from two geographically distant locations within minutes."""
    events = []
    # First auth: normal location
    loc1 = {"city": profile["primary_location"], "lat": profile["primary_lat"], "lng": profile["primary_lng"]}
    # Second auth: far location within 10-30 minutes
    loc2 = random.choice(FOREIGN_LOCATIONS)
    gap_minutes = random.randint(5, 25)

    for i, (ts_offset, loc, success) in enumerate([
        (0, loc1, True),
        (gap_minutes * 60, loc2, True),
    ]):
        ts = base_ts + timedelta(seconds=ts_offset)
        events.append({
            "event_id":           str(uuid.uuid4()),
            "entity_id":          identity["entity_id"],
            "entity_type":        identity["entity_type"],
            "timestamp":          ts.isoformat(),
            "source_ip":          random_ip(),
            "geo_location":       loc["city"],
            "latitude":           round(loc["lat"] + np.random.normal(0, 0.01), 4),
            "longitude":          round(loc["lng"] + np.random.normal(0, 0.01), 4),
            "resource_accessed":  random.choice(profile["common_resources"]),
            "auth_method":        profile["preferred_auth"],
            "auth_success":       success,
            "session_duration":   round(random.uniform(30, 300), 1),
            "command_sequence":   json.dumps(random.choice(profile["typical_commands"]) if profile["typical_commands"] else ["login"]),
            "device_fingerprint": random.choice(profile["known_devices"]),
            "department":         identity.get("department"),
            "label":              "impossible_travel",
        })
    return events


def inject_credential_stuffing(identities: list[dict], profiles: dict, base_ts: datetime) -> list[dict]:
    """One IP attempts auth against many different identities with high failure rate."""
    events = []
    attack_ip = f"203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    targets = random.sample(identities, k=min(random.randint(20, 40), len(identities)))
    for i, target in enumerate(targets):
        ts = base_ts + timedelta(seconds=i * random.randint(3, 15))
        profile = profiles[target["entity_id"]]
        loc = random.choice(FOREIGN_LOCATIONS)
        success = random.random() < 0.05  # 5% success rate
        events.append({
            "event_id":           str(uuid.uuid4()),
            "entity_id":          target["entity_id"],
            "entity_type":        target["entity_type"],
            "timestamp":          ts.isoformat(),
            "source_ip":          attack_ip,
            "geo_location":       loc["city"],
            "latitude":           round(loc["lat"] + np.random.normal(0, 0.05), 4),
            "longitude":          round(loc["lng"] + np.random.normal(0, 0.05), 4),
            "resource_accessed":  "/auth/login",
            "auth_method":        "password",
            "auth_success":       success,
            "session_duration":   round(random.uniform(0.5, 5.0), 1),
            "command_sequence":   json.dumps(["login_attempt"]),
            "device_fingerprint": random_device_fingerprint(),
            "department":         target.get("department"),
            "label":              "credential_stuffing",
        })
    return events


def inject_lateral_movement(identity: dict, profile: dict, base_ts: datetime) -> list[dict]:
    """Identity suddenly accesses unusual systems outside historical behavior."""
    events = []
    # Access resources from a DIFFERENT department/type
    all_resources = []
    for dept_resources in RESOURCES_BY_DEPT.values():
        all_resources.extend(dept_resources)
    # Filter out normal resources
    normal = set(profile["common_resources"])
    unusual = [r for r in all_resources if r not in normal]
    accessed = random.sample(unusual, k=min(random.randint(5, 10), len(unusual)))

    # Unusual commands
    unusual_cmds = [
        ["net use \\\\server\\admin$", "dir /s"],
        ["psexec \\\\target cmd"],
        ["wmic /node:target process call create cmd"],
        ["mimikatz privilege::debug"],
        ["nmap -sV 10.0.0.0/24"],
    ]

    for i, resource in enumerate(accessed):
        ts = base_ts + timedelta(minutes=i * random.randint(2, 8))
        events.append({
            "event_id":           str(uuid.uuid4()),
            "entity_id":          identity["entity_id"],
            "entity_type":        identity["entity_type"],
            "timestamp":          ts.isoformat(),
            "source_ip":          random_ip(profile["ip_prefix"]),
            "geo_location":       profile["primary_location"],
            "latitude":           round(profile["primary_lat"] + np.random.normal(0, 0.01), 4),
            "longitude":          round(profile["primary_lng"] + np.random.normal(0, 0.01), 4),
            "resource_accessed":  resource,
            "auth_method":        profile["preferred_auth"],
            "auth_success":       True,
            "session_duration":   round(random.uniform(60, 1200), 1),
            "command_sequence":   json.dumps(random.choice(unusual_cmds)),
            "device_fingerprint": random.choice(profile["known_devices"]),
            "department":         identity.get("department"),
            "label":              "lateral_movement",
        })
    return events


def inject_device_spoofing(identity: dict, profile: dict, base_ts: datetime) -> list[dict]:
    """Identity appears using an unknown device fingerprint."""
    events = []
    unknown_device = random_device_fingerprint() + "-SPOOFED"
    ts = base_ts + timedelta(minutes=random.randint(0, 60))
    events.append({
        "event_id":           str(uuid.uuid4()),
        "entity_id":          identity["entity_id"],
        "entity_type":        identity["entity_type"],
        "timestamp":          ts.isoformat(),
        "source_ip":          random_ip(profile["ip_prefix"]),
        "geo_location":       profile["primary_location"],
        "latitude":           round(profile["primary_lat"] + np.random.normal(0, 0.01), 4),
        "longitude":          round(profile["primary_lng"] + np.random.normal(0, 0.01), 4),
        "resource_accessed":  random.choice(profile["common_resources"]),
        "auth_method":        profile["preferred_auth"],
        "auth_success":       True,
        "session_duration":   round(random.uniform(300, 3600), 1),
        "command_sequence":   json.dumps(random.choice(profile["typical_commands"]) if profile["typical_commands"] else ["login"]),
        "device_fingerprint": unknown_device,
        "department":         identity.get("department"),
        "label":              "device_spoofing",
    })
    return events


def inject_low_slow_exfiltration(identity: dict, profile: dict, base_ts: datetime) -> list[dict]:
    """Gradual off-hours access and increasing data access over many events."""
    events = []
    # Off-hours times
    normal_hours_set = set(profile["normal_hours"])
    off_hours = [h for h in range(24) if h not in normal_hours_set] or [2, 3, 4]

    # Spread over multiple days
    num_events = random.randint(8, 15)
    # Gradually increasing session duration and breadth
    all_resources = list(RESOURCES_BY_DEPT.values())
    flat_resources = [r for sublist in all_resources for r in sublist]
    unusual = [r for r in flat_resources if r not in profile["common_resources"]]

    for i in range(num_events):
        day = random.randint(0, 20) + i * 3  # spread over ~60 days
        day = min(day, 89)
        hour = random.choice(off_hours)
        ts = START_DATE + timedelta(days=day, hours=hour, minutes=random.randint(0, 59))

        # Gradually access more unusual resources
        resource = unusual[i % len(unusual)] if unusual else random.choice(profile["common_resources"])

        events.append({
            "event_id":           str(uuid.uuid4()),
            "entity_id":          identity["entity_id"],
            "entity_type":        identity["entity_type"],
            "timestamp":          ts.isoformat(),
            "source_ip":          random_ip(profile["ip_prefix"]),
            "geo_location":       profile["primary_location"],
            "latitude":           round(profile["primary_lat"] + np.random.normal(0, 0.01), 4),
            "longitude":          round(profile["primary_lng"] + np.random.normal(0, 0.01), 4),
            "resource_accessed":  resource,
            "auth_method":        profile["preferred_auth"],
            "auth_success":       True,
            "session_duration":   round(300 + i * 120 + random.uniform(0, 60), 1),  # increasing duration
            "command_sequence":   json.dumps(["export_data", f"--volume={100 + i * 50}MB"]),
            "device_fingerprint": random.choice(profile["known_devices"]),
            "department":         identity.get("department"),
            "label":              "low_slow_exfiltration",
        })
    return events


def inject_insider_drift(identity: dict, profile: dict, base_ts: datetime) -> list[dict]:
    """Gradual behavioral changes over time: hours shift, resources shift."""
    events = []
    normal_hours = profile["normal_hours"]
    num_events = random.randint(10, 20)

    for i in range(num_events):
        day = i * random.randint(3, 5)
        day = min(day, 89)

        # Hours gradually drift later
        drift = i // 3
        drifted_hour = (max(normal_hours) + drift) % 24

        ts = START_DATE + timedelta(days=day, hours=drifted_hour, minutes=random.randint(0, 59))

        # Resources gradually drift to unusual ones
        all_dept_resources = RESOURCES_BY_DEPT.get(identity.get("department") or identity["entity_type"], [])
        all_other = [r for dept_res in RESOURCES_BY_DEPT.values() for r in dept_res if r not in profile["common_resources"]]

        if i < 5:
            resource = random.choice(profile["common_resources"])
        elif i < 10:
            resource = random.choice(all_dept_resources) if all_dept_resources else random.choice(profile["common_resources"])
        else:
            resource = random.choice(all_other) if all_other else random.choice(profile["common_resources"])

        events.append({
            "event_id":           str(uuid.uuid4()),
            "entity_id":          identity["entity_id"],
            "entity_type":        identity["entity_type"],
            "timestamp":          ts.isoformat(),
            "source_ip":          random_ip(profile["ip_prefix"]),
            "geo_location":       profile["primary_location"],
            "latitude":           round(profile["primary_lat"] + np.random.normal(0, 0.02), 4),
            "longitude":          round(profile["primary_lng"] + np.random.normal(0, 0.02), 4),
            "resource_accessed":  resource,
            "auth_method":        profile["preferred_auth"],
            "auth_success":       True,
            "session_duration":   round(random.uniform(profile["session_dur_min"], profile["session_dur_max"]) * (1 + i * 0.05), 1),
            "command_sequence":   json.dumps(random.choice(profile["typical_commands"]) if profile["typical_commands"] else ["login"]),
            "device_fingerprint": random.choice(profile["known_devices"]),
            "department":         identity.get("department"),
            "label":              "insider_drift",
        })
    return events


# ─── Main generation function ─────────────────────────────────────────────────

def generate_dataset() -> tuple[list[dict], list[dict]]:
    """
    Generate all identities and events.
    Returns (identities, events).
    """
    print("Building identity profiles...")
    identities: list[dict] = []
    dept_cycle = DEPARTMENTS * (NUM_USERS // len(DEPARTMENTS) + 1)
    for i in range(NUM_USERS):
        dept = dept_cycle[i]
        identities.append(build_identity(i + 1, "user", dept))
    for i in range(NUM_SERVICE_ACCOUNTS):
        identities.append(build_identity(i + 1, "service_account", None))
    for i in range(NUM_EDGE_DEVICES):
        identities.append(build_identity(i + 1, "edge_device", None))

    profiles = {ident["entity_id"]: ident["profile"] for ident in identities}

    # Decide event count per identity (weighted by type)
    normal_target = int(TARGET_EVENTS * (1 - ANOMALY_RATE))
    events_per_identity = [
        max(80, int(np.random.normal(normal_target // len(identities), 30)))
        for _ in identities
    ]
    total_normal = sum(events_per_identity)

    print(f"Generating ~{total_normal} normal events...")
    all_events: list[dict] = []

    for identity, n_events in zip(identities, events_per_identity):
        profile = profiles[identity["entity_id"]]
        for _ in range(n_events):
            all_events.append(make_normal_event(identity, profile))

    # ─── Anomaly injection ────────────────────────────────────────────────────
    print("Injecting anomalous events...")

    user_identities = [i for i in identities if i["entity_type"] == "user"]

    # Brute force: 5 distinct incidents
    for _ in range(5):
        target = random.choice(user_identities)
        base = START_DATE + timedelta(days=random.randint(0, 89), hours=random.randint(0, 23))
        all_events.extend(inject_brute_force(target, profiles[target["entity_id"]], base))

    # Impossible travel: 8 incidents
    for _ in range(8):
        target = random.choice(user_identities)
        base = START_DATE + timedelta(days=random.randint(0, 89), hours=random.randint(6, 18))
        all_events.extend(inject_impossible_travel(target, profiles[target["entity_id"]], base))

    # Credential stuffing: 3 campaigns
    for _ in range(3):
        base = START_DATE + timedelta(days=random.randint(0, 89), hours=random.randint(0, 23))
        all_events.extend(inject_credential_stuffing(identities, profiles, base))

    # Lateral movement: 6 incidents
    for _ in range(6):
        target = random.choice(user_identities)
        base = START_DATE + timedelta(days=random.randint(0, 89), hours=random.randint(8, 20))
        all_events.extend(inject_lateral_movement(target, profiles[target["entity_id"]], base))

    # Device spoofing: 12 incidents
    for _ in range(12):
        target = random.choice(identities)
        base = START_DATE + timedelta(days=random.randint(0, 89))
        all_events.extend(inject_device_spoofing(target, profiles[target["entity_id"]], base))

    # Low-and-slow exfiltration: 5 incidents
    for _ in range(5):
        target = random.choice(user_identities)
        base = START_DATE
        all_events.extend(inject_low_slow_exfiltration(target, profiles[target["entity_id"]], base))

    # Insider drift: 4 identities
    for _ in range(4):
        target = random.choice(user_identities)
        base = START_DATE
        all_events.extend(inject_insider_drift(target, profiles[target["entity_id"]], base))

    # Shuffle events (randomize order)
    random.shuffle(all_events)

    total = len(all_events)
    anomalous = sum(1 for e in all_events if e["label"] != "normal")
    normal = total - anomalous
    pct_normal = 100.0 * normal / total
    pct_anomaly = 100.0 * anomalous / total

    print(f"Dataset complete: {total} events total")
    print(f"  Normal:    {normal} ({pct_normal:.2f}%)")
    print(f"  Anomalous: {anomalous} ({pct_anomaly:.2f}%)")

    return identities, all_events
