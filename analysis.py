import argparse
import collections
import csv
import os
import queue
import statistics
import threading
from datetime import datetime

FIELDS = ["timestamp", "source", "user", "client_ip", "op", "file",
          "bytes", "transfer_s", "mbps", "resp_ms", "status"]
MB = 1024 * 1024


def calc_mbps(nbytes, seconds):
    return round(nbytes / MB / seconds, 3) if nbytes and seconds and seconds > 0 else 0.0


class StatsCollector:
    

    def __init__(self, csv_path="server_stats.csv"):
        self.csv_path = csv_path
        self.records = []
        self._lock = threading.Lock()
        self._q = queue.Queue()
        self._thread = None

    def start(self):
        new = not os.path.exists(self.csv_path) or os.path.getsize(self.csv_path) == 0
        self._file = open(self.csv_path, "a", newline="")
        self._writer = csv.DictWriter(self._file, fieldnames=FIELDS)
        if new:
            self._writer.writeheader()
            self._file.flush()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()
        return self

    def _drain(self):
        while True:
            row = self._q.get()
            if row is None:
                break
            self._writer.writerow(row)
            self._file.flush()

    def record(self, **kw):
        row = {f: kw.get(f, "") for f in FIELDS}
        row["timestamp"] = datetime.now().isoformat(timespec="milliseconds")
        if not row["mbps"] and row["bytes"] and row["transfer_s"]:
            row["mbps"] = calc_mbps(row["bytes"], row["transfer_s"])
        with self._lock:
            self.records.append(row)
        if self._thread:
            self._q.put(row)

    def stop(self):
        if self._thread:
            self._q.put(None)
            self._thread.join(timeout=2)
            self._file.close()
            self._thread = None

    def summary(self):
        with self._lock:
            return summarize(list(self.records))


def load_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def summarize(rows):
    groups = collections.defaultdict(list)
    for r in rows:
        if r.get("status", "OK") == "OK":
            groups[(r["source"], r["op"])].append(r)
    out = []
    for (src, op), rs in sorted(groups.items()):
        rates = [x for x in (_num(r["mbps"]) for r in rs) if x]
        times = [x for x in (_num(r["transfer_s"]) for r in rs) if x]
        resp = [x for x in (_num(r["resp_ms"]) for r in rs) if x is not None]
        out.append({
            "source": src, "op": op, "count": len(rs),
            "avg_mbps": round(statistics.mean(rates), 2) if rates else 0,
            "min_mbps": round(min(rates), 2) if rates else 0,
            "max_mbps": round(max(rates), 2) if rates else 0,
            "avg_transfer_s": round(statistics.mean(times), 3) if times else 0,
            "avg_resp_ms": round(statistics.mean(resp), 2) if resp else 0,
        })
    return out


def print_summary(summary):
    hdr = f"{'source':8}{'op':10}{'n':>4}{'avg MB/s':>10}{'min':>8}{'max':>8}{'avg xfer s':>12}{'avg resp ms':>13}"
    print(hdr)
    print("-" * len(hdr))
    for s in summary:
        print(f"{s['source']:8}{s['op']:10}{s['count']:>4}{s['avg_mbps']:>10}{s['min_mbps']:>8}"
              f"{s['max_mbps']:>8}{s['avg_transfer_s']:>12}{s['avg_resp_ms']:>13}")


def make_plots(rows, outdir="plots"):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed (pip install matplotlib) - skipping plots")
        return
    os.makedirs(outdir, exist_ok=True)
    ok = [r for r in rows if r.get("status") == "OK"]
    xfer = [r for r in ok if r["op"] in ("UPLOAD", "DOWNLOAD") and _num(r["mbps"])]

    s = [x for x in summarize(ok) if x["op"] in ("UPLOAD", "DOWNLOAD")]
    if s:
        labels = [f"{x['source']}\n{x['op']}" for x in s]
        plt.figure(figsize=(7, 4))
        plt.bar(labels, [x["avg_mbps"] for x in s])
        plt.ylabel("Average data rate (MB/s)")
        plt.title("Upload / Download data rate")
        plt.tight_layout(); plt.savefig(os.path.join(outdir, "data_rate.png")); plt.close()

    s = summarize(ok)
    if s:
        labels = [f"{x['source']}\n{x['op']}" for x in s]
        plt.figure(figsize=(max(7, len(s) * 0.8), 4))
        plt.bar(labels, [x["avg_resp_ms"] for x in s])
        plt.ylabel("Average response time (ms)")
        plt.title("System response time by operation")
        plt.tight_layout(); plt.savefig(os.path.join(outdir, "response_time.png")); plt.close()

    if xfer:
        plt.figure(figsize=(7, 4))
        for op in ("UPLOAD", "DOWNLOAD"):
            pts = [(float(r["bytes"]) / MB, float(r["transfer_s"])) for r in xfer
                   if r["op"] == op and r["source"] == "server"]
            if pts:
                plt.scatter(*zip(*pts), label=op)
        plt.xlabel("File size (MB)"); plt.ylabel("Transfer time (s)")
        plt.title("Transfer time vs file size (server view)"); plt.legend()
        plt.tight_layout(); plt.savefig(os.path.join(outdir, "size_vs_time.png")); plt.close()
    print(f"Plots written to ./{outdir}/")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Summarize a stats CSV produced by server/client")
    ap.add_argument("csv", nargs="?", default="server_stats.csv")
    ap.add_argument("--plots", action="store_true", help="also write PNG graphs (needs matplotlib)")
    args = ap.parse_args()
    data = load_csv(args.csv)
    print_summary(summarize(data))
    if args.plots:
        make_plots(data)
