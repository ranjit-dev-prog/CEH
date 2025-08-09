import argparse
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue, Empty

from dateutil import parser as dtparser
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.console import Console
from rich.text import Text

console = Console()

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    console.print("[yellow]Scapy not installed - sniffing disabled[/yellow]")

TAIL_POLL = 0.2
RECENT_MAX = 500
BRUTE_WINDOW = 60
BRUTE_THRESHOLD = 8
RATE_WINDOW = 10
RATE_THRESHOLD = 40
SCAN_WINDOW = 20
UNIQUE_URI_THRESHOLD = 30

# Regex for Combined Log Format — IP, timestamp, method, url, status, and user-agent (we parse but won't show UA)
COMMON_LOG_REGEX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)

RULES = [
    {"id": "MITRE_BRUTE", "name": "Brute Force Login Attempts", "sev": "HIGH", "mitre": ["T1110"], "type": "behavior"},
    {"id": "MITRE_RATE", "name": "High Request Rate", "sev": "MED", "mitre": ["T1071"], "type": "behavior"},
    {"id": "MITRE_SCAN", "name": "URI Scanning", "sev": "MED", "mitre": ["T1595"], "type": "behavior"},
]

recent_events = deque(maxlen=RECENT_MAX)
alerts = deque(maxlen=1000)
summary = defaultdict(lambda: defaultdict(int))

ip_timestamps = defaultdict(deque)
ip_failed = defaultdict(deque)
ip_uri_hist = defaultdict(deque)
ip_uri_set = defaultdict(lambda: defaultdict(int))

stop_event = threading.Event()
line_q = Queue()


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat()


def short(text, length=140):
    if not text:
        return "-"
    text = str(text)
    return text if len(text) <= length else text[:length] + "…"


def parse_log_line(line):
    line = line.strip()
    if not line:
        return None
    match = COMMON_LOG_REGEX.search(line)
    if not match:
        console.print(f"[yellow]Log line did not match regex:[/yellow] {line}")
        return None
    gd = match.groupdict()
    try:
        parsed_ts = dtparser.parse(gd.get("time"))
        ts_iso = parsed_ts.isoformat()
    except Exception:
        ts_iso = now_iso()

    # Method and URL extracted directly from log line without fallback to placeholder
    return {
        "ip": gd.get("ip"),
        "method": gd.get("method") or "UNKNOWN_METHOD",
        "url": gd.get("path") or "/",
        "status": gd.get("status") or "safe",
        "ua": gd.get("ua") or "Unknown User-Agent",
        "time": ts_iso,
        "dst": None,
    }


def add_alert(rule, event, extra=""):
    alert = {
        "time": now_iso(),
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "mitre": rule["mitre"],
        "severity": rule["sev"],
        "event": event,
        "extra": extra,
    }
    alerts.appendleft(alert)
    src_ip = event.get("ip", "-")
    summary[src_ip][rule["id"]] += 1


def brute_detector(event):
    ip = event.get("ip")
    try:
        status_code = int(event.get("status"))
    except Exception:
        status_code = 0

    if status_code in (401, 403):
        now_ts = time.time()
        dq = ip_failed[ip]
        dq.append(now_ts)
        while dq and now_ts - dq[0] > BRUTE_WINDOW:
            dq.popleft()

        if len(dq) >= BRUTE_THRESHOLD:
            rule = next((r for r in RULES if r["id"] == "MITRE_BRUTE"), None)
            if rule:
                add_alert(rule, event, extra=f"{len(dq)} failed auths in {BRUTE_WINDOW}s")
                dq.clear()


def rate_detector(event):
    ip = event.get("ip")
    now_ts = time.time()
    dq = ip_timestamps[ip]
    dq.append(now_ts)
    while dq and now_ts - dq[0] > RATE_WINDOW:
        dq.popleft()

    if len(dq) >= RATE_THRESHOLD:
        rule = next((r for r in RULES if r["id"] == "MITRE_RATE"), None)
        if rule:
            add_alert(rule, event, extra=f"{len(dq)} reqs in {RATE_WINDOW}s")
            dq.clear()


def scan_detector(event):
    ip = event.get("ip")
    uri = event.get("url") or "-"
    now_ts = time.time()

    history = ip_uri_hist[ip]
    history.append((now_ts, uri))
    ip_uri_set[ip][uri] += 1

    while history and now_ts - history[0][0] > SCAN_WINDOW:
        old_ts, old_uri = history.popleft()
        ip_uri_set[ip][old_uri] -= 1
        if ip_uri_set[ip][old_uri] <= 0:
            del ip_uri_set[ip][old_uri]

    unique_count = len(ip_uri_set[ip])
    if unique_count >= UNIQUE_URI_THRESHOLD:
        rule = next((r for r in RULES if r["id"] == "MITRE_SCAN"), None)
        if rule:
            add_alert(rule, event, extra=f"{unique_count} unique URIs in {SCAN_WINDOW}s")
            ip_uri_set[ip].clear()
            ip_uri_hist[ip].clear()


def signature_match(event):
    for rule in RULES:
        if rule.get("type") != "sig":
            continue
        pattern = rule.get("pattern")
        apply_to = rule.get("apply_to", "url")
        if apply_to == "method":
            target_text = event.get("method", "")
        else:
            target_text = f"{event.get('url', '')} {event.get('ua', '')}"
        if pattern and pattern.search(target_text):
            add_alert(rule, event, extra="signature match")


def process_event(event):
    if not event:
        return
    # No placeholders — show real data or blank fallback handled in parse_log_line & pkt_handler
    recent_events.appendleft(event)
    brute_detector(event)
    rate_detector(event)
    scan_detector(event)
    signature_match(event)


def tail_file(path, output_queue, stop_evt):
    try:
        with open(path, "r", errors="ignore") as f:
            f.seek(0, 2)
            while not stop_evt.is_set():
                line = f.readline()
                if not line:
                    time.sleep(TAIL_POLL)
                    continue
                output_queue.put(line)
    except Exception as e:
        console.print(f"[red]Tail error: {e}[/red]")


def parse_http_payload(payload_bytes):
    try:
        text = payload_bytes.decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        if not lines:
            return None
        request_line = lines[0].split()
        if len(request_line) < 3:
            return None
        method, path, protocol = request_line[0], request_line[1], request_line[2]
        headers = {}
        for line in lines[1:]:
            if line == "":
                break
            parts = line.split(":", 1)
            if len(parts) == 2:
                headers[parts[0].strip().lower()] = parts[1].strip()
        return {
            "method": method,
            "url": path,
            "protocol": protocol,
            "headers": headers,
            "raw_text": text[:500],
        }
    except Exception as e:
        console.print(f"[yellow]HTTP payload parse failed: {e}[/yellow]")
        return None


def pkt_handler(pkt):
    try:
        if IP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = getattr(pkt, "sport", "-")
        dport = getattr(pkt, "dport", "-")
        proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "IP")
        payload = b""

        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if proto == "TCP" and dport == 80:
                http_info = parse_http_payload(payload)
                if http_info:
                    event = {
                        "time": now_iso(),
                        "ip": src,
                        "dst": dst,
                        "method": http_info.get("method") or "UNKNOWN_METHOD",
                        "url": http_info.get("url") or "/",
                        "status": "safe",
                        "ua": "",  # Remove UA field completely
                        "note": f"{proto} {sport}->{dport}",
                        "payload": short(http_info.get("raw_text", ""), 200),
                    }
                    process_event(event)
                    return
        # fallback event
        event = {
            "time": now_iso(),
            "ip": src,
            "dst": dst,
            "method": "UNKNOWN_METHOD",
            "url": "/",
            "status": "safe",
            "ua": "",  # Removed UA
            "note": f"{proto} {sport}->{dport}",
            "payload": short(payload.decode("utf-8", errors="ignore"), 200),
        }
        process_event(event)
    except Exception as e:
        console.print(f"[red]Packet handling error: {e}[/red]")


def start_sniff(filter_expr=None):
    if not SCAPY_AVAILABLE:
        console.print("[yellow]Scapy not installed — sniffing disabled[/yellow]")
        return
    try:
        sniff(prn=pkt_handler, store=False, filter=filter_expr)
    except Exception as e:
        console.print(f"[red]Sniff error: {e}[/red]")


def severity_color(sev):
    sev = sev.upper()
    if sev == "HIGH":
        return "bold red"
    elif sev == "MED":
        return "yellow"
    elif sev == "LOW":
        return "green"
    else:
        return "white"


def build_recent_table():
    table = Table(title="Recent Events (newest first)", expand=True)
    table.add_column("Time", width=20)
    table.add_column("SRC", width=16)
    table.add_column("DST", width=16)
    table.add_column("Method", width=12)
    table.add_column("URL", width=60, overflow="fold")
    table.add_column("Severity", width=10)

    alert_map = {}
    for alert in alerts:
        ev = alert.get("event", {})
        key = (ev.get("ip"), ev.get("time"))
        sev = alert.get("severity", "LOW")
        rule_name = alert.get("rule_name", "")
        concise = f"{sev.upper()} {rule_name.split()[0]}"
        alert_map[key] = Text(concise, style=severity_color(sev))

    for event in list(recent_events)[:30]:
        method = event.get("method") or "UNKNOWN_METHOD"
        url = short(event.get("url") or "/", 60)
        key = (event.get("ip"), event.get("time"))
        alert_text = alert_map.get(key, Text("LOW", style=severity_color("LOW")))
        table.add_row(
            event.get("time", "-"),
            event.get("ip", "-"),
            event.get("dst", "-"),
            method,
            url,
            alert_text,
        )
    return table


def build_alerts_table():
    table = Table(title="Alerts", expand=True)
    table.add_column("Severity", width=8)
    table.add_column("Time", width=20)
    table.add_column("Rule Name", width=30)
    table.add_column("Extra Info", width=40)
    table.add_column("MITRE ATT&CK", width=20)

    if not alerts:
        table.add_row("No alerts", "", "", "", "")
        return table

    for alert in list(alerts)[:10]:
        table.add_row(
            alert["severity"],
            alert["time"],
            alert["rule_name"],
            alert["extra"],
            ",".join(alert["mitre"]),
        )
    return table


def consume_lines(line_queue, stop_evt):
    while not stop_evt.is_set():
        try:
            line = line_queue.get(timeout=0.5)
        except Empty:
            continue
        if line is None:
            break
        event = parse_log_line(line)
        if event:
            event["dst"] = None
            process_event(event)


def print_summary():
    console.print("\n[bold]Summary of detections:[/bold]")
    rows = []
    for src_ip, rules_dict in summary.items():
        for rule_id, count in rules_dict.items():
            rows.append([src_ip, rule_id, count])

    if not rows:
        console.print("No detections.")
        return

    tbl = Table(title="Summary")
    tbl.add_column("SRC IP")
    tbl.add_column("Rule ID")
    tbl.add_column("Count", justify="right")

    for row in rows:
        tbl.add_row(str(row[0]), row[1], str(row[2]))

    console.print(tbl)


def main():
    parser = argparse.ArgumentParser(description="Realtime offline IDS with MITRE ATT&CK mapping")
    parser.add_argument("target", help="Target domain or IP (for display)")
    parser.add_argument(
        "access_log",
        nargs="?",
        help="Path to access log file (if omitted, sniffing mode is enabled)",
    )
    parser.add_argument("--pcap-filter", help="BPF filter expression for sniffing", default=None)
    args = parser.parse_args()

    if args.access_log:
        if not Path(args.access_log).exists():
            console.print(f"[red]Access log file does not exist: {args.access_log}[/red]")
            return
        t = threading.Thread(target=tail_file, args=(args.access_log, line_q, stop_event), daemon=True)
        t.start()
        consumer = threading.Thread(target=consume_lines, args=(line_q, stop_event), daemon=True)
        consumer.start()
    else:
        if not SCAPY_AVAILABLE:
            console.print("[red]Scapy not available, cannot sniff packets[/red]")
            return
        sniff_thread = threading.Thread(target=start_sniff, args=(args.pcap_filter,), daemon=True)
        sniff_thread.start()

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=3),
    )
    layout["main"].split_row(
        Layout(name="recent"),
        Layout(name="alerts", size=50),
    )

    layout["header"].update(Text("Realtime IDS with MITRE ATT&CK Mapping", style="bold cyan"))
    layout["footer"].update(Text("[Q] Quit", style="bold green"))

    with Live(layout, refresh_per_second=4, screen=True):
        while True:
            try:
                layout["recent"].update(build_recent_table())
                layout["alerts"].update(build_alerts_table())
                time.sleep(0.25)
            except KeyboardInterrupt:
                stop_event.set()
                break

    print_summary()


if __name__ == "__main__":
    main()
