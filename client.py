"""
client.py - Command-line client for the CNT3004 file server.

  python client.py                       interactive shell
  python client.py <server-ip> [port]    auto-run CONNECT, then prompt for LOGIN

Commands (case-insensitive):
  CONNECT <ip> [port]            open a TCP connection to the server
  LOGIN <user>                   authenticate (password prompt is hidden; never sent in clear)
  UPLOAD <local_file> [remote_folder]
  DOWNLOAD <name|ID> [--drop MB] download; resumes automatically from a partial .part file.
                                 --drop N simulates a network failure after N MB (for the demo)
  DELETE <name|ID>
  DIR [folder]
  SUBFOLDER create|delete <path>
  STATS                          show this session's performance numbers
  LOGOUT | HELP | QUIT

The CloudClient class has no input()/print() dependency on the shell, so
loadtest.py reuses it to generate concurrent load.
"""
import getpass
import hashlib
import os
import shlex
import socket
import sys
import time

import protocol as P
from analysis import StatsCollector, calc_mbps, summarize, print_summary

MB = 1024 * 1024


class CloudClient:
    def __init__(self, download_dir="client_downloads", stats_csv="client_stats.csv", verbose=True):
        self.sock = None
        self.user = None
        self.download_dir = download_dir
        self.verbose = verbose
        self.stats = StatsCollector(stats_csv).start()
        self.last_progress = 0.0

    # ---------------------------------------------------------------- plumbing
    @property
    def connected(self):
        return self.sock is not None

    def _drop(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock, self.user = None, None

    def _need(self, logged_in=True):
        if not self.connected:
            raise ConnectionError("Not connected. Use CONNECT <ip> [port]")
        if logged_in and not self.user:
            raise PermissionError("Not logged in. Use LOGIN <user>")

    def _request(self, msg):
        """Send a command and return (reply, response_time_ms)."""
        t0 = time.perf_counter()
        P.send_msg(self.sock, msg)
        reply = P.recv_msg(self.sock)
        return reply, round((time.perf_counter() - t0) * 1000, 3)

    def _record(self, op, file="", nbytes=0, secs=0.0, resp_ms="", status="OK"):
        """Store locally AND report to the server so it holds both sides' numbers."""
        mbps = calc_mbps(nbytes, secs)
        self.stats.record(source="client", user=self.user or "", op=op, file=file, bytes=nbytes,
                          transfer_s=round(secs, 4), mbps=mbps, resp_ms=resp_ms, status=status)
        if self.connected and self.user:
            try:
                P.send_msg(self.sock, {"cmd": "STATS", "op": op, "file": file, "bytes": nbytes,
                                       "transfer_s": round(secs, 4), "mbps": mbps,
                                       "resp_ms": resp_ms, "status": status})
                P.recv_msg(self.sock)
            except OSError:
                pass

    def _progress(self, label, done, total, t0, force=False):
        if not self.verbose:
            return
        now = time.perf_counter()
        if force or now - self.last_progress > 0.25:
            self.last_progress = now
            pct = 100 * done / total if total else 100
            rate = done / MB / max(now - t0, 1e-9)
            print(f"\r  {label}: {done/MB:,.1f}/{total/MB:,.1f} MB ({pct:5.1f}%)  {rate:6.1f} MB/s", end="", flush=True)
            if force:
                print()

    # ---------------------------------------------------------- connect / auth
    def connect(self, ip, port=P.DEFAULT_PORT):
        self._drop()
        self.sock = socket.create_connection((ip, int(port)), timeout=10)
        self.sock.settimeout(120)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return P.recv_msg(self.sock).get("msg", "Connected")

    def login(self, user, password):
        self._need(logged_in=False)
        r, ms1 = self._request({"cmd": "AUTH_START", "user": user})
        if r.get("status") != "OK":
            return False, r.get("msg", "Login failed")
        key = P.derive_key(password, r["salt"], r["iterations"])     # password stays on this machine
        r, ms2 = self._request({"cmd": "AUTH_PROOF", "proof": P.make_proof(key, r["nonce"])})
        if r.get("status") == "OK":
            self.user = user
            self._record("LOGIN", resp_ms=round(ms1 + ms2, 3))
            return True, r["msg"]
        return False, r.get("msg", "Login failed")

    def logout(self):
        if self.connected:
            try:
                self._request({"cmd": "LOGOUT"})
            except OSError:
                pass
        self._drop()

    # ---------------------------------------------------------------- UPLOAD
    def upload(self, local_path, remote_dir="", overwrite=None):
        """overwrite: True/False to decide automatically, None to ask the user via input()."""
        self._need()
        if not os.path.isfile(local_path):
            return {"status": "ERROR", "msg": f"Local file not found: {local_path}"}
        size = os.path.getsize(local_path)
        key = "/".join(x for x in (remote_dir.strip("/"), os.path.basename(local_path)) if x)
        r, resp_ms = self._request({"cmd": "UPLOAD", "path": key, "size": size})
        if r["status"] == "EXISTS":
            ans = overwrite
            if ans is None:
                ans = input(f"  {r['msg']}. Overwrite? [y/N] ").strip().lower() == "y"
            P.send_msg(self.sock, {"cmd": "UPLOAD_CONFIRM", "overwrite": bool(ans)})
            r = P.recv_msg(self.sock)
        if r["status"] != "READY":
            return r                                        # ERROR / CANCELLED

        h, sent, t0 = hashlib.sha256(), 0, time.perf_counter()
        with open(local_path, "rb") as f:
            while True:
                block = f.read(P.CHUNK)
                if not block:
                    break
                self.sock.sendall(block)
                h.update(block)
                sent += len(block)
                self._progress("Uploading", sent, size, t0)
        final = P.recv_msg(self.sock)                       # server confirms after it has written the file
        secs = time.perf_counter() - t0
        self._progress("Uploading", size, size, t0, force=True)
        if final.get("status") == "OK":
            final["integrity_ok"] = final.get("sha256") == h.hexdigest()
            final.update(bytes=size, secs=secs, mbps=calc_mbps(size, secs), resp_ms=resp_ms)
            self._record("UPLOAD", key, size, secs, resp_ms)
        return final

    # -------------------------------------------------------------- DOWNLOAD
    def download(self, name, drop_after_mb=None):
        """Chunked download into <download_dir>/<name>.part; resumes if a .part file exists."""
        self._need()
        os.makedirs(self.download_dir, exist_ok=True)
        part = os.path.join(self.download_dir, name.replace("/", "__") + ".part")
        offset = os.path.getsize(part) if os.path.exists(part) else 0

        r, resp_ms = self._request({"cmd": "DOWNLOAD", "path": name, "offset": offset})
        if r.get("code") == "BAD_OFFSET":                    # stale partial file -> start over
            os.remove(part)
            offset = 0
            r, resp_ms = self._request({"cmd": "DOWNLOAD", "path": name, "offset": 0})
        if r["status"] != "OK":
            return r

        size, final_path = r["size"], os.path.join(self.download_dir, r["name"])
        resumed = offset > 0
        if resumed and self.verbose:
            print(f"  Resuming '{r['name']}' from byte {offset:,} ({offset/MB:,.1f} MB already on disk)")
        got, t0 = 0, time.perf_counter()
        try:
            with open(part, "ab" if resumed else "wb") as f:
                while offset + got < size:
                    chunk = self.sock.recv(min(P.CHUNK, size - offset - got))
                    if not chunk:
                        raise ConnectionError("Server closed the connection")
                    f.write(chunk)
                    got += len(chunk)
                    self._progress("Downloading", offset + got, size, t0)
                    if drop_after_mb and got >= drop_after_mb * MB:
                        f.flush()
                        self._drop()                         # simulate a sudden network failure
                        raise ConnectionError(f"[simulated] connection dropped after {got/MB:.1f} MB")
        except (ConnectionError, socket.timeout, OSError) as e:
            secs = time.perf_counter() - t0
            self._drop()
            if self.verbose:
                print()
            return {"status": "INTERRUPTED", "msg": f"{e}. {offset+got:,} of {size:,} bytes kept in {part}",
                    "bytes": got, "have": offset + got, "total": size, "secs": secs}

        secs = time.perf_counter() - t0
        self._progress("Downloading", size, size, t0, force=True)
        ok = P.sha256_file(part) == r["sha256"]               # SHA-256 integrity check on the whole file
        if ok:
            os.replace(part, final_path)
        else:
            os.remove(part)
        res = {"status": "OK" if ok else "ERROR", "path": final_path, "bytes": got, "total": size,
               "resumed_from": offset, "secs": secs, "mbps": calc_mbps(got, secs), "resp_ms": resp_ms,
               "integrity_ok": ok, "sha256": r["sha256"],
               "msg": "SHA-256 verified" if ok else "SHA-256 mismatch - partial file discarded, retry"}
        self._record("DOWNLOAD", name, got, secs, resp_ms, "OK" if ok else "FAIL")
        return res

    # ------------------------------------------------------- DELETE / DIR / etc
    def delete(self, name):
        self._need()
        r, ms = self._request({"cmd": "DELETE", "path": name})
        self._record("DELETE", name, resp_ms=ms, status="OK" if r["status"] == "OK" else "FAIL")
        return r

    def dir(self, path=""):
        self._need()
        r, ms = self._request({"cmd": "DIR", "path": path})
        self._record("DIR", path, resp_ms=ms, status="OK" if r["status"] == "OK" else "FAIL")
        return r

    def subfolder(self, action, path):
        self._need()
        r, ms = self._request({"cmd": "SUBFOLDER", "action": action, "path": path})
        self._record("SUBFOLDER_" + action.upper(), path, resp_ms=ms, status="OK" if r["status"] == "OK" else "FAIL")
        return r


# ================================================================== the shell
HELP = __doc__.split("Commands (case-insensitive):")[1].split("The CloudClient")[0]


def show(r):
    tag = {"OK": "[OK]", "CANCELLED": "[--]"}.get(r.get("status"), "[!!]")
    print(f"{tag} {r.get('msg', r.get('status'))}")


def shell(client):
    print("CNT3004 file client. Type HELP for commands.")
    while True:
        try:
            line = input(f"{client.user + '@' if client.user else ''}cloud> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        try:
            a = shlex.split(line)
        except ValueError as e:
            print(f"[!!] {e}")
            continue
        cmd, args = a[0].upper(), a[1:]
        try:
            if cmd in ("QUIT", "EXIT"):
                break
            elif cmd == "HELP":
                print(HELP)
            elif cmd == "CONNECT" and args:
                print("[OK]", client.connect(args[0], args[1] if len(args) > 1 else P.DEFAULT_PORT))
            elif cmd == "LOGIN":
                user = args[0] if args else input("Username: ")
                ok, msg = client.login(user, getpass.getpass("Password: "))
                print(("[OK] " if ok else "[!!] ") + msg)
            elif cmd == "LOGOUT":
                client.logout()
                print("[OK] Logged out and disconnected")
            elif cmd == "UPLOAD" and args:
                r = client.upload(args[0], args[1] if len(args) > 1 else "")
                show(r)
                if r.get("status") == "OK":
                    print(f"     {r['bytes']/MB:,.1f} MB in {r['secs']:.2f}s = {r['mbps']} MB/s | "
                          f"ID {r['id']} | integrity {'OK' if r['integrity_ok'] else 'MISMATCH'}")
            elif cmd == "DOWNLOAD" and args:
                drop = float(args[args.index("--drop") + 1]) if "--drop" in args else None
                r = client.download(args[0], drop)
                show(r)
                if r.get("status") == "OK":
                    print(f"     saved {r['path']} | received {r['bytes']/MB:,.1f} MB this session "
                          f"(resumed from byte {r['resumed_from']:,}) in {r['secs']:.2f}s = {r['mbps']} MB/s")
            elif cmd == "DELETE" and args:
                show(client.delete(args[0]))
            elif cmd == "DIR":
                r = client.dir(args[0] if args else "")
                if r["status"] != "OK":
                    show(r)
                else:
                    print(f"Contents of /{r['path']}")
                    for d in r["folders"]:
                        print(f"  [DIR]  {d}/")
                    for f in r["files"]:
                        print(f"  {f['id']:7} {f['type']:6} {f['size']/MB:10,.2f} MB  {f['name']}   (owner: {f['owner']})")
                    if not r["folders"] and not r["files"]:
                        print("  (empty)")
            elif cmd == "SUBFOLDER" and len(args) >= 2:
                show(client.subfolder(args[0], args[1]))
            elif cmd == "STATS":
                print_summary(summarize(client.stats.records))
            else:
                print("[!!] Unknown or incomplete command. Type HELP.")
        except (ConnectionError, socket.timeout) as e:
            print(f"[!!] {e}")
            if "Not connected" not in str(e):
                client._drop()
                print("     Connection lost. Use CONNECT again (partial downloads are kept and will resume).")
        except PermissionError as e:
            print(f"[!!] {e}")
    client.logout()
    client.stats.stop()
    print("Disconnected from the server.")


if __name__ == "__main__":
    c = CloudClient()
    if len(sys.argv) > 1:
        try:
            print("[OK]", c.connect(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else P.DEFAULT_PORT))
        except OSError as e:
            print(f"[!!] Could not connect: {e}")
    shell(c)
