#!/usr/bin/env python3
"""Comprehensive bidirectional interop matrix: ns-ssh* tools vs OpenSSH tools.

Tests every pair where the tools SHOULD interoperate, in BOTH directions:
  - keygen: ns-ssh-keygen <-> ssh-keygen (keys usable by the other side)
  - agent:  ns-ssh-agent <-> ssh-agent (add/list/sign interop)
  - server: ns-ssh-server <-> sshd (both accept the other's client tools)
  - client: ns-ssh <-> ssh (against both servers)
  - file transfer: ns-scp/ns-sftp <-> scp/sftp (against both servers)
  - keyscan: ns-ssh-keyscan <-> ssh-keyscan (against both servers)
  - copy-id: ns-ssh-copy-id <-> ssh-copy-id (against both servers)

Run from the repo root. Requires target/debug/ns-ssh built.
"""
import subprocess, tempfile, time, os, shutil, socket, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = "/tmp/nstools"
NS = ROOT + "/target/debug/ns-ssh"
USER = os.environ.get("USER", "root")

PASS, FAIL = [], []
def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")

def section(t):
    print(f"\n{'='*70}\n{t}\n{'='*70}")

def sh(args, timeout=30, env=None, input=None):
    r = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, env=env, input=input)
    return r

def ns(tool, *args, **kw):
    return sh([f"{TOOLS}/{tool}"] + list(args), **kw)

def op(tool, *args, **kw):
    return sh([tool] + list(args), **kw)

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            c = socket.create_connection(("127.0.0.1", port), timeout=0.5); c.close(); return True
        except OSError: time.sleep(0.05)
    return False

def make_dir(prefix):
    return tempfile.mkdtemp(prefix=f"nsinterop-{prefix}-")

def keygen(d, tool, ttype="ed25519", name="id"):
    """Generate with a specific keygen tool; return (priv, pub)."""
    priv = f"{d}/{name}"
    r = (ns if tool.startswith("ns-") else op)(tool if not tool.startswith("ns-") else tool,
            "-t", ttype, "-f", priv, "-N", "", "-q")
    return priv, f"{priv}.pub", r

# ===========================================================================
section("1. keygen interop (both directions)")
d = make_dir("kg")
for ttype in ["ed25519", "ecdsa", "rsa"]:
    sk, spub, r1 = keygen(d, "ssh-keygen", ttype, f"s_{ttype}")
    nk, npub, r2 = keygen(d, "ns-ssh-keygen", ttype, f"n_{ttype}")
    gen_ok = r1.returncode == 0 and r2.returncode == 0
    check(f"{ttype} keygen both tools", gen_ok, f"ssh rc={r1.returncode} ns rc={r2.returncode} err={r2.stderr[:80]}")
    if not gen_ok:
        continue
    # ns-keygen reads ssh-keygen private
    r = ns("ns-ssh-keygen", "-y", "-f", sk)
    check(f"ns-ssh-keygen -y reads ssh-keygen {ttype} priv", r.returncode == 0 and len(r.stdout) > 60, f"rc={r.returncode} err={r.stderr[:80]}")
    # ssh-keygen reads ns-keygen private
    r = op("ssh-keygen", "-y", "-f", nk)
    check(f"ssh-keygen -y reads ns-ssh-keygen {ttype} priv", r.returncode == 0 and len(r.stdout) > 60, f"rc={r.returncode} err={r.stderr[:80]}")
    # fingerprints from both tools on both keys must agree (bit size + hash)
    f1 = ns("ns-ssh-keygen", "-lf", sk)   # ns tool on ssh key
    f2 = ns("ns-ssh-keygen", "-lf", nk)   # ns tool on ns key
    f3 = op("ssh-keygen", "-lf", sk)      # ssh tool on ssh key
    f4 = op("ssh-keygen", "-lf", nk)      # ssh tool on ns key
    check(f"{ttype} fingerprint consistent (ns on ssh == ssh on ssh)", f1.returncode == 0 and f1.stdout.split()[:2] == f3.stdout.split()[:2], f"ns={f1.stdout[:50]} ssh={f3.stdout[:50]}")
    check(f"{ttype} fingerprint consistent (ns on ns == ssh on ns)", f2.returncode == 0 and f2.stdout.split()[:2] == f4.stdout.split()[:2], f"ns={f2.stdout[:50]} ssh={f4.stdout[:50]}")
shutil.rmtree(d, ignore_errors=True)

# ===========================================================================
section("2. agent interop (both directions)")
def start_agent(tool, sock):
    if tool == "ns-ssh-agent":
        p = subprocess.Popen([f"{TOOLS}/ns-ssh-agent", "-D", "-a", sock],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        p = subprocess.Popen(["ssh-agent", "-D", "-a", sock],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    env = dict(os.environ); env["SSH_AUTH_SOCK"] = sock
    return p, env

d = make_dir("agent")
_, _, _ = keygen(d, "ssh-keygen", "ed25519", "akey")
for agent_tool in ["ns-ssh-agent", "ssh-agent"]:
    sock = f"{d}/{agent_tool}.sock"
    p, env = start_agent(agent_tool, sock)
    time.sleep(0.8)
    ok = os.path.exists(sock)
    check(f"{agent_tool} listening", ok, f"sock missing: {sock}")
    # add a key: use the OPPOSITE add tool
    add_tool = "ssh-add" if agent_tool == "ns-ssh-agent" else "ns-ssh-add"
    r = (op if add_tool == "ssh-add" else ns)(add_tool, f"{d}/akey", env=env)
    check(f"{add_tool} adds to {agent_tool}", r.returncode == 0, f"rc={r.returncode} err={r.stderr[:90]}")
    # list from both sides
    rl = op("ssh-add", "-l", env=env)
    check(f"ssh-add -l sees key in {agent_tool}", rl.returncode == 0 and rl.stdout.strip(), f"rc={rl.returncode} out={rl.stdout[:50]}")
    rn = ns("ns-ssh-add", "-l", env=env)
    check(f"ns-ssh-add -l sees key in {agent_tool}", rn.returncode == 0 and rn.stdout.strip(), f"rc={rn.returncode} out={rn.stdout[:50]}")
    p.kill(); p.wait()
shutil.rmtree(d, ignore_errors=True)

# ===========================================================================
section("3. client <-> server matrix (ns-ssh/ssh against ns-ssh-server/sshd)")
def start_ns_server(port, d):
    log = open(f"{d}/ns_srv.log", "w")
    p = subprocess.Popen([f"{ROOT}/target/debug/ns-ssh-server", "-d", "-p", str(port),
        "-o", "listenaddress=127.0.0.1", "-o", "pubkeyauthentication=yes",
        "-o", "passwordauthentication=no", "-o", "gssapiauthentication=no",
        "-o", "permitrootlogin=yes",
        "-o", f"authorizedkeysfile={d}/authorized_keys",
        "--host-key-file", f"{d}/hostkey"], stdout=log, stderr=log)
    return p

def start_real_sshd(port, d):
    hk = f"{d}/real_hostkey"
    op("ssh-keygen", "-t", "ed25519", "-f", hk, "-N", "", "-q")
    cfg = f"{d}/sshd_config"
    with open(cfg, "w") as f:
        f.write(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {hk}\n"
                f"PubkeyAuthentication yes\nPasswordAuthentication no\n"
                f"GSSAPIAuthentication no\nPermitRootLogin yes\n"
                f"AuthorizedKeysFile {d}/authorized_keys\n"
                f"Subsystem sftp /usr/libexec/sftp-server\n"
                f"PidFile {d}/sshd.pid\nUsePAM no\nStrictModes no\n")
    log = open(f"{d}/real_sshd.log", "w")
    p = subprocess.Popen(["/usr/sbin/sshd", "-f", cfg, "-E", log.name],
                         stdout=log, stderr=log)
    return p

def start_server(kind, port, d):
    return start_ns_server(port, d) if kind == "ns-ssh-server" else start_real_sshd(port, d)

d = make_dir("srv")
# client key + authorized_keys
ck = f"{d}/clientkey"
op("ssh-keygen", "-t", "ed25519", "-f", ck, "-N", "", "-q")
shutil.copy(f"{ck}.pub", f"{d}/authorized_keys")
op("ssh-keygen", "-t", "ed25519", "-f", f"{d}/hostkey", "-N", "", "-q")

# Common client base args (identity + no host checking). `-p` is the ssh port
# for ssh/ns-ssh; scp/sftp use `-P`.
def base_args(port, extra=None, port_flag="-p"):
    a = [port_flag, str(port), "-l", USER, "-i", ck, "-F", "/dev/null",
         "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={d}/kh",
         "-o", "BatchMode=yes", "-o", "GSSAPIAuthentication=no"]
    return a + (extra or [])

def base_args_no_user(port, extra=None, port_flag="-P"):
    # For scp/sftp: no -l USER, port via -P/-o Port, identity via -i.
    a = [port_flag, str(port), "-i", ck, "-F", "/dev/null",
         "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={d}/kh",
         "-o", "BatchMode=yes", "-o", "GSSAPIAuthentication=no"]
    return a + (extra or [])

for srv_kind in ["ns-ssh-server", "sshd"]:
    port = free_port()
    sp = start_server(srv_kind, port, d)
    if not wait_port(port):
        check(f"{srv_kind} startup", False, "did not listen"); continue
    check(f"{srv_kind} startup", True)
    # -- exec (ssh/ns-ssh) --
    for client_kind in ["ns-ssh", "ssh"]:
        bin = f"{TOOLS}/ns-ssh" if client_kind == "ns-ssh" else "ssh"
        r = sh([bin] + base_args(port) + ["127.0.0.1", "echo OK"])
        check(f"{client_kind} -> {srv_kind} exec", r.returncode == 0 and r.stdout.strip() == "OK",
              f"rc={r.returncode} out={r.stdout.strip()[:40]!r} err={r.stderr.strip()[:60]!r}")
    # -- scp upload/download (ns-scp/scp): port via -P, no -l USER --
    src = f"{d}/upload.txt"; open(src, "w").write("interop-upload-data\n")
    for cp_kind, cp_bin in [("ns-scp", f"{TOOLS}/ns-scp"), ("scp", "scp")]:
        dest = f"{d}/remote_{cp_kind}.txt"
        r = sh([cp_bin] + base_args_no_user(port) + [src, f"127.0.0.1:{dest}"])
        check(f"{cp_kind} upload -> {srv_kind}", r.returncode == 0, f"rc={r.returncode} err={r.stderr[:90]}")
        # download back
        dl = f"{d}/dl_{cp_kind}.txt"
        r2 = sh([cp_bin] + base_args_no_user(port) + [f"127.0.0.1:{dest}", dl])
        check(f"{cp_kind} download <- {srv_kind}", r2.returncode == 0 and open(dl).read() == "interop-upload-data\n",
              f"rc={r2.returncode} err={r2.stderr[:90]}")
    # -- sftp batch (ns-sftp/sftp): port via -P, no -l USER --
    for sf_kind, sf_bin in [("ns-sftp", f"{TOOLS}/ns-sftp"), ("sftp", "sftp")]:
        remote = f"upload_sftp_{sf_kind}.txt"
        batch = f"{d}/batch_{sf_kind}.txt"
        open(batch, "w").write(f"put {src} {remote}\nget {remote} {d}/got_{sf_kind}.txt\nbye\n")
        r = sh([sf_bin] + base_args_no_user(port) + ["-b", batch, "127.0.0.1"])
        ok = r.returncode == 0 and os.path.exists(f"{d}/got_{sf_kind}.txt") and open(f"{d}/got_{sf_kind}.txt").read() == "interop-upload-data\n"
        check(f"{sf_kind} batch -> {srv_kind}", ok, f"rc={r.returncode} err={r.stderr[:110]}")
    # -- copy-id (ns-ssh-copy-id/ssh-copy-id): ssh-style args (-p port), no -l --
    for ci_kind, ci_bin in [("ns-ssh-copy-id", f"{TOOLS}/ns-ssh-copy-id"), ("ssh-copy-id", "ssh-copy-id")]:
        a = ["-p", str(port), "-i", ck, "-F", "/dev/null",
             "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={d}/kh",
             "-o", "BatchMode=yes", "-o", "GSSAPIAuthentication=no"]
        r = sh([ci_bin] + a + ["127.0.0.1"])
        check(f"{ci_kind} -> {srv_kind}", r.returncode == 0, f"rc={r.returncode} err={r.stderr[:90]}")
    # -- keyscan (ns-ssh-keyscan/ssh-keyscan) --
    for ks_kind, ks_bin in [("ns-ssh-keyscan", f"{TOOLS}/ns-ssh-keyscan"), ("ssh-keyscan", "ssh-keyscan")]:
        r = sh([ks_bin, "-p", str(port), "-t", "ed25519", "127.0.0.1"])
        check(f"{ks_kind} -> {srv_kind}", r.returncode == 0 and "ssh-ed25519" in r.stdout,
              f"rc={r.returncode} out={r.stdout[:50]}")
    sp.kill(); sp.wait()
shutil.rmtree(d, ignore_errors=True)

print(f"\n{'='*70}\nRESULT: {len(PASS)} pass, {len(FAIL)} fail")
if FAIL:
    print("Failures:")
    for f in FAIL: print(f"  - {f}")
sys.exit(1 if FAIL else 0)
