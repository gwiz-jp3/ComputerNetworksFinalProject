import argparse
import os
import threading
import time

from client import CloudClient, MB
import protocol as P


def worker(i, a, results):
    c = CloudClient(download_dir=f"loadtest_downloads/c{i}", stats_csv="loadtest_stats.csv", verbose=False)
    try:
        c.connect(a.ip, a.port)
        ok, msg = c.login(a.user, a.password)
        if not ok:
            results[i] = ("login failed", 0, 0)
            return
        base = os.path.basename(a.file)
        remote_dir = f"load_c{i}"
        c.subfolder("create", remote_dir)
        up = c.upload(a.file, remote_dir, overwrite=True)
        dn = c.download(f"{remote_dir}/{base}")
        c.delete(f"{remote_dir}/{base}")
        c.subfolder("delete", remote_dir)
        results[i] = ("ok", up.get("mbps", 0), dn.get("mbps", 0))
    except Exception as e:                                   # keep the experiment going
        results[i] = (f"error: {e}", 0, 0)
    finally:
        c.logout()
        c.stats.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("ip")
    ap.add_argument("--port", type=int, default=P.DEFAULT_PORT)
    ap.add_argument("--clients", type=int, default=4)
    ap.add_argument("--file", required=True)
    ap.add_argument("--user", default="student")
    ap.add_argument("--password", default="cnt3004")
    a = ap.parse_args()
    results = {}
    threads = [threading.Thread(target=worker, args=(i, a, results)) for i in range(a.clients)]
    t0 = time.perf_counter()
    [t.start() for t in threads]
    [t.join() for t in threads]
    wall = time.perf_counter() - t0
    print(f"\n{a.clients} concurrent clients, {os.path.getsize(a.file)/MB:.1f} MB file, wall time {wall:.2f}s")
    for i, (st, up, dn) in sorted(results.items()):
        print(f"  client {i}: {st:10} upload {up} MB/s   download {dn} MB/s")
