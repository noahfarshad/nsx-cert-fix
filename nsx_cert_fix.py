#!/usr/bin/env python3
"""Replace expired NSX Manager certificates and delete failed edge deployments, through the API.

  python3 nsx_cert_fix.py --manager nsx.example.com                       # plan: reads, writes nothing
  python3 nsx_cert_fix.py --manager nsx.example.com --commit              # new certificate per node and for the VIP
  python3 nsx_cert_fix.py --manager nsx.example.com --delete-edges edge01,edge02 --commit

Certificates are self-signed, 825 days, with the node's FQDN and address as SANs, made here with openssl
and imported; that is how NSX ships. Each node's API certificate is applied one node at a time, the
cluster (VIP) certificate last; the API is unavailable on a node for about a minute while it applies.
The data plane is not touched. To use your CA instead: --csr-dir DIR writes one CSR and key
per name for signing; --import-dir DIR imports the signed certificates from there and applies them.
Password: NSX_PASSWORD, or prompted. Nothing secret is printed.

Certificate verification is off for these calls. The certificate you are replacing is the one that
would have been checked, and it is already expired.
"""
import argparse
import base64
import datetime
import getpass
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def http(host, H, path, method="GET", body=None, timeout=90):
    data = json.dumps(body).encode() if body is not None else None
    hdrs = dict(H, Accept="application/json")
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request("https://%s%s" % (host, path), data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"_raw": raw[:300].decode("utf-8", "replace")}
    except Exception as e:
        return 0, {"_error": str(e)}


def served_cert(host, port=443):
    """(subject CN, notAfter) of the certificate a host serves now, or (None, error)."""
    try:
        pem = ssl.get_server_certificate((host, port), timeout=15)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
        out = subprocess.run(["openssl", "x509", "-noout", "-subject", "-enddate", "-in", fh.name],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True).stdout
        os.unlink(fh.name)
        cn = out.split("CN")[-1].split("\n")[0].strip(" =") if "CN" in out else "?"
        na = out.split("notAfter=")[-1].strip() if "notAfter=" in out else "?"
        return cn, na
    except Exception as e:
        return None, str(e)


def make_self_signed(fqdn, ip, days, outdir):
    key, crt = os.path.join(outdir, fqdn + ".key"), os.path.join(outdir, fqdn + ".crt")
    san = "subjectAltName=DNS:%s,DNS:%s%s" % (fqdn, fqdn.split(".")[0], (",IP:%s" % ip) if ip else "")
    p = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", str(days),
                        "-keyout", key, "-out", crt, "-subj", "/CN=%s" % fqdn, "-addext", san,
                        "-addext", "basicConstraints=critical,CA:FALSE",
                        "-addext", "extendedKeyUsage=serverAuth,clientAuth", "-addext", "keyUsage=digitalSignature,keyEncipherment"],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    if p.returncode:
        sys.exit("openssl failed for %s: %s" % (fqdn, p.stdout[-300:]))
    os.chmod(key, 0o600)
    return open(crt).read(), open(key).read()


def make_csr(fqdn, ip, outdir):
    key, csr = os.path.join(outdir, fqdn + ".key"), os.path.join(outdir, fqdn + ".csr")
    san = "subjectAltName=DNS:%s,DNS:%s%s" % (fqdn, fqdn.split(".")[0], (",IP:%s" % ip) if ip else "")
    p = subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-sha256", "-nodes", "-keyout", key, "-out", csr,
                        "-subj", "/CN=%s" % fqdn, "-addext", san], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True)
    if p.returncode:
        sys.exit("openssl failed for %s: %s" % (fqdn, p.stdout[-300:]))
    os.chmod(key, 0o600)
    return csr


def import_cert(host, H, name, pem, key):
    st, b = http(host, H, "/api/v1/trust-management/certificates?action=import",
                 "POST", {"display_name": name, "pem_encoded": pem, "private_key": key})
    res = (b.get("results") or [{}])[0] if isinstance(b, dict) else {}
    if st not in (200, 201) or not res.get("id"):
        return None, "import HTTP %s %s" % (st, str(b.get("error_message") or b)[:200])
    return res["id"], None


def apply_cert(host, H, cert_id, node_id=None):
    q = "&service_type=API&node_id=%s" % node_id if node_id else "&service_type=MGMT_CLUSTER"
    st, b = http(host, H, "/api/v1/trust-management/certificates/%s?action=apply_certificate%s" % (cert_id, q), "POST", timeout=180)
    return st in (200, 201, 202, 204), "HTTP %s %s" % (st, str((b or {}).get("error_message") or "")[:200])


def wait_api(host, H, secs=240):
    t0 = time.time()
    while time.time() - t0 < secs:
        st, _b = http(host, H, "/api/v1/cluster/status", timeout=20)
        if st == 200:
            return True
        time.sleep(10)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manager", required=True, help="NSX Manager VIP FQDN")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--days", type=int, default=825)
    ap.add_argument("--csr-dir", help="write a CSR and key per name here, for the CA, and stop")
    ap.add_argument("--import-dir", help="apply the CA-signed <fqdn>.crt found here (keys from --csr-dir)")
    ap.add_argument("--delete-edges", help="comma-separated edge names whose deployment failed, to delete")
    ap.add_argument("--commit", action="store_true", help="write. Without it: plan only")
    a = ap.parse_args()
    pw = os.environ.get("NSX_PASSWORD") or getpass.getpass("NSX %s '%s' password: " % (a.manager, a.user))
    H = {"Authorization": "Basic " + base64.b64encode(("%s:%s" % (a.user, pw)).encode()).decode()}
    outdir = "nsx_cert_fix_%s" % time.strftime("%Y%m%d-%H%M%S")
    os.makedirs(outdir, 0o700)

    st, nodes = http(a.manager, H, "/api/v1/cluster/nodes")
    if st != 200:
        sys.exit("cannot read the cluster nodes on %s: HTTP %s %s" % (a.manager, st, nodes))
    mgrs = []
    for n in nodes.get("results") or []:
        if not n.get("manager_role"):
            continue
        fq = n.get("fqdn") or n.get("display_name")
        ip = (n.get("appliance_mgmt_listen_addr") or "").split("/")[0]
        mgrs.append({"id": n.get("id"), "fqdn": fq, "ip": ip})
    vip_ip = None
    try:
        vip_ip = socket.gethostbyname(a.manager)
    except OSError:
        pass
    print("\n %s: %d manager nodes" % (a.manager, len(mgrs)))
    for n in mgrs + [{"id": None, "fqdn": a.manager, "ip": vip_ip}]:
        cn, na = served_cert(n["ip"] or n["fqdn"])
        exp = False
        try:
            exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z") < datetime.datetime.now()
        except ValueError:
            pass
        n["expired"] = exp
        print("   %-32s %-16s serves CN=%s  notAfter=%s  %s" % (n["fqdn"], n["ip"] or "", cn, na, "EXPIRED" if exp else "valid"))
    todo = [n for n in mgrs] + [{"id": None, "fqdn": a.manager, "ip": vip_ip, "vip": True}]

    edges = []
    if a.delete_edges:
        st, tns = http(a.manager, H, "/api/v1/transport-nodes?node_types=EdgeNode&page_size=1000")
        want = {x.strip().lower() for x in a.delete_edges.split(",") if x.strip()}
        for t in (tns.get("results") or []) if st == 200 else []:
            if str(t.get("display_name")).lower() in want:
                st2, s2 = http(a.manager, H, "/api/v1/transport-nodes/%s/state" % t["id"])
                state = (s2.get("state") if st2 == 200 else "?")
                dst = ((s2.get("node_deployment_state") or {}).get("state") if st2 == 200 else "?")
                edges.append({"id": t["id"], "name": t["display_name"], "state": state, "dstate": dst})
        print("\n edges to delete:")
        for e in edges:
            print("   %-16s %s  %s / %s" % (e["name"], e["id"], e["state"], e["dstate"]))
        missing = want - {e["name"].lower() for e in edges}
        if missing:
            print("   not on this manager: %s" % ", ".join(sorted(missing)))

    if a.csr_dir:
        os.makedirs(a.csr_dir, 0o700, exist_ok=True)
        for n in todo:
            print("   CSR %s" % make_csr(n["fqdn"], n["ip"], a.csr_dir))
        print("\n Have the CA sign each CSR as a server certificate; put <fqdn>.crt (with the chain) beside it, then run with --import-dir %s --commit" % a.csr_dir)
        return

    if not a.commit:
        print("\n plan only. --commit replaces the certificate on %s and applies it; --delete-edges … --commit deletes the edges named."
              % ", ".join(n["fqdn"] for n in todo))
        return

    for e in edges:
        st, b = http(a.manager, H, "/api/v1/transport-nodes/%s" % e["id"], "DELETE", timeout=180)
        if st not in (200, 202, 204):
            st, b = http(a.manager, H, "/api/v1/transport-nodes/%s?force=true" % e["id"], "DELETE", timeout=180)
        print("   delete %-16s HTTP %s %s" % (e["name"], st, str((b or {}).get("error_message") or "")[:120]))
    if a.delete_edges and not (a.import_dir or any(n["expired"] for n in todo)):
        return

    for n in todo:
        label = "cluster VIP" if n.get("vip") else "node"
        if a.import_dir:
            crt, key = os.path.join(a.import_dir, n["fqdn"] + ".crt"), os.path.join(a.csr_dir or a.import_dir, n["fqdn"] + ".key")
            if not (os.path.exists(crt) and os.path.exists(key)):
                print("   %-32s no %s or key: skipped" % (n["fqdn"], crt))
                continue
            pem, keypem = open(crt).read(), open(key).read()
        else:
            pem, keypem = make_self_signed(n["fqdn"], n["ip"], a.days, outdir)
        cid, err = import_cert(a.manager, H, "%s %s" % (n["fqdn"], time.strftime("%Y-%m-%d")), pem, keypem)
        if err:
            print("   %-32s %s" % (n["fqdn"], err))
            continue
        ok, msg = apply_cert(a.manager, H, cid, node_id=n["id"] if not n.get("vip") else None)
        print("   %-32s %s certificate %s: %s" % (n["fqdn"], label, cid, "applied" if ok else "NOT applied, " + msg))
        if ok:
            time.sleep(15)
            wait_api(a.manager, H)
    print("\n now served:")
    for n in todo:
        cn, na = served_cert(n["ip"] or n["fqdn"])
        print("   %-32s CN=%s  notAfter=%s" % (n["fqdn"], cn, na))
    print("\n keys and certificates in %s (mode 700); keep or delete" % outdir)


if __name__ == "__main__":
    main()
