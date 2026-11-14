# /// script
# requires-python = ">=3.11"
# ///

import argparse
import json
import re
import statistics
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime


def ssh(host: str, cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command on the remote host via SSH."""
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", host, cmd],
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed (exit {result.returncode}):\n"
            f"  cmd: {cmd}\n"
            f"  stdout: {result.stdout.strip()}\n"
            f"  stderr: {result.stderr.strip()}"
        )
    return result


def ssh_out(host: str, cmd: str) -> str:
    return ssh(host, cmd).stdout.strip()


@dataclass
class FragCounters:
    reasm_reqds: int = 0
    reasm_oks: int = 0
    reasm_fails: int = 0
    frag_oks: int = 0
    frag_fails: int = 0
    frag_creates: int = 0

    def __sub__(self, other: "FragCounters") -> "FragCounters":
        return FragCounters(
            reasm_reqds=self.reasm_reqds - other.reasm_reqds,
            reasm_oks=self.reasm_oks - other.reasm_oks,
            reasm_fails=self.reasm_fails - other.reasm_fails,
            frag_oks=self.frag_oks - other.frag_oks,
            frag_fails=self.frag_fails - other.frag_fails,
            frag_creates=self.frag_creates - other.frag_creates,
        )


@dataclass
class SpeedtestResult:
    dl_iqm_ms: float = 0.0
    dl_high_ms: float = 0.0
    jitter_ms: float = 0.0
    raw: str = ""
    error: str = ""


@dataclass
class TunnelMTUResult:
    interface: str = ""
    path_mtu: int = 0
    usable_mtu: int = 0
    configured_mtu: int = 0
    total_overhead: int = 0
    probe_count: int = 0
    duration_ms: int = 0
    pass_: bool | None = None
    error: str = ""
    raw: str = ""


@dataclass
class PhaseResult:
    name: str
    configured_mtu: int
    tunnelmtu: list[TunnelMTUResult] = field(default_factory=list)
    frag_deltas: list[FragCounters] = field(default_factory=list)
    speedtests: list[SpeedtestResult] = field(default_factory=list)


SNMP_AWK = """awk '/^Ip:/{if(!hdr){split($0,h);hdr=1;next} for(i=1;i<=NF;i++) if(h[i]~/Frag|Reasm/) printf h[i]" "$i" "; print ""}' /proc/net/snmp"""


def read_frag_counters(host: str) -> FragCounters:
    out = ssh_out(host, SNMP_AWK)
    if not out:
        raise RuntimeError("read_frag_counters: empty output from /proc/net/snmp")
    parts = out.split()
    it = iter(parts)
    pairs = {k: int(v) for k, v in zip(it, it)}
    return FragCounters(
        reasm_reqds=pairs.get("ReasmReqds", 0),
        reasm_oks=pairs.get("ReasmOKs", 0),
        reasm_fails=pairs.get("ReasmFails", 0),
        frag_oks=pairs.get("FragOKs", 0),
        frag_fails=pairs.get("FragFails", 0),
        frag_creates=pairs.get("FragCreates", 0),
    )


def run_tunnelmtu(host: str, iface: str, target: str, keep_netns: bool = False) -> TunnelMTUResult:
    result = TunnelMTUResult(interface=iface)
    keep_flag = " --keep-netns" if keep_netns else ""
    # tunnelmtu exits non-zero on WARN, so parse the JSON either way
    r = ssh(host, f"./tunnelmtu mtu -i {iface} {target} --json{keep_flag}", check=False)
    result.raw = r.stdout.strip()
    try:
        data = json.loads(result.raw)
    except json.JSONDecodeError:
        result.error = r.stderr.strip() or f"no JSON output (exit {r.returncode})"
        return result
    result.path_mtu = data.get("path_mtu", 0)
    result.usable_mtu = data.get("usable_mtu", 0)
    result.configured_mtu = data.get("configured_mtu", 0)
    result.total_overhead = data.get("total_overhead", 0)
    result.probe_count = data.get("probe_count", 0)
    result.duration_ms = data.get("duration_ms", 0)
    result.pass_ = data.get("pass")
    result.error = data.get("error", "")
    return result


def run_speedtest(host: str, speedtest_cmd: str) -> SpeedtestResult:
    result = SpeedtestResult()
    r = ssh(host, f"{speedtest_cmd} 2>&1", check=False)
    result.raw = r.stdout.strip()

    for line in result.raw.splitlines():
        if line.strip().startswith('{"type":"result"'):
            try:
                js = json.loads(line.strip())
            except json.JSONDecodeError:
                break
            result.dl_iqm_ms = js.get("download", {}).get("latency", {}).get("iqm", 0.0)
            result.dl_high_ms = js.get("download", {}).get("latency", {}).get("high", 0.0)
            result.jitter_ms = js.get("ping", {}).get("jitter", 0.0)
            return result

    # no result line means the run failed; keep zeros out of the medians
    result.error = f"no speedtest result (exit {r.returncode})"
    return result


def get_iface_mtu(host: str, iface: str) -> int:
    out = ssh_out(host, f"ip -j link show {iface}")
    data = json.loads(out)
    return data[0]["mtu"]


def ping_boundary(host: str, target: str, usable_mtu: int) -> dict:
    """Send 10 pings at usable_mtu and usable_mtu+1 to prove the hard cliff."""
    netns_check = ssh(host, "ip netns list 2>/dev/null | grep -qw tunnelmtu", check=False)
    if netns_check.returncode != 0:
        return {
            "error": "tunnelmtu netns not present; the last sweep must run with --keep-netns",
            "valid": False,
        }

    results: dict = {"valid": True}
    for label, payload in [
        ("at_limit", usable_mtu - 28),        # largest IP datagram that should pass
        ("over_limit", usable_mtu - 28 + 1),  # one byte over
    ]:
        cmd = f"ip netns exec tunnelmtu ping -M do -c 10 -W 2 -s {payload} {target} 2>&1"
        r = ssh(host, cmd, check=False)
        out = r.stdout + r.stderr

        loss = 100
        if m := re.search(r"(\d+)% packet loss", out):
            loss = int(m.group(1))

        results[label] = {
            "payload_bytes": payload,
            "total_bytes": payload + 28,
            "packet_loss_pct": loss,
            "output": out.strip(),
        }
    return results


def _as_dict(obj) -> dict:
    d = vars(obj).copy()
    d.pop("raw", None)
    return d


def status_of(w: TunnelMTUResult) -> str:
    if w.pass_ is True:
        return "PASS"
    if w.pass_ is False:
        return "WARN"
    return "ERROR"


def print_section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def print_phase(phase: PhaseResult) -> None:
    print_section(phase.name)
    print(f"  Configured MTU: {phase.configured_mtu}")

    for w in phase.tunnelmtu:
        print(f"\n  tunnelmtu [{w.interface}]")
        print(f"    Path MTU:   {w.path_mtu} B")
        print(f"    Usable MTU: {w.usable_mtu} B")
        print(f"    Overhead:   {w.total_overhead} B")
        print(f"    Probes:     {w.probe_count}  ({w.duration_ms} ms)")
        print(f"    Status:     {status_of(w)}")
        if w.error:
            print(f"    Error:      {w.error}")

    if phase.frag_deltas:
        print("\n  Fragmentation counters (per speedtest):")
        print(f"    {'Run':<5} {'ReasmReqds':>12} {'ReasmOKs':>10} {'ReasmFails':>12} {'FragCreates':>13}")
        for i, d in enumerate(phase.frag_deltas, 1):
            print(f"    {i:<5} {d.reasm_reqds:>12} {d.reasm_oks:>10} {d.reasm_fails:>12} {d.frag_creates:>13}")

    if phase.speedtests:
        ok = [s for s in phase.speedtests if not s.error]
        print(f"\n  Speedtest latency results ({len(phase.speedtests)} runs):")
        print(f"    {'Run':<5} {'DL IQM ms':>11} {'DL High ms':>12} {'Jitter ms':>11}")
        for i, s in enumerate(phase.speedtests, 1):
            err = f"  ERROR: {s.error}" if s.error else ""
            print(f"    {i:<5} {s.dl_iqm_ms:>11.1f} {s.dl_high_ms:>12.1f} {s.jitter_ms:>11.1f}{err}")
        if ok:
            iqm = statistics.median(s.dl_iqm_ms for s in ok)
            high = statistics.median(s.dl_high_ms for s in ok)
            jitter = statistics.median(s.jitter_ms for s in ok)
            print(f"    {'median':<5} {iqm:>11.1f} {high:>12.1f} {jitter:>11.1f}")


def print_comparison(before: PhaseResult, after: PhaseResult) -> None:
    print_section("RESULTS SUMMARY")

    total_before = sum(d.reasm_reqds for d in before.frag_deltas)
    total_after = sum(d.reasm_reqds for d in after.frag_deltas)
    print("\n  Fragmentation (ReasmReqds total across all speedtest runs):")
    print(f"    Before fix:  {total_before}")
    print(f"    After fix:   {total_after}")
    if total_before > 0:
        reduction = (total_before - total_after) / total_before * 100
        print(f"    Reduction:   {reduction:.0f}%")

    ok_before = [s for s in before.speedtests if not s.error]
    ok_after = [s for s in after.speedtests if not s.error]
    if ok_before and ok_after:
        print(f"\n  Latency metrics (median over {len(ok_before)} / {len(ok_after)} runs):")
        print(f"    {'Metric':<20} {'Before':>10} {'After':>10} {'Delta':>10}")
        for label, attr in [("DL IQM ms", "dl_iqm_ms"), ("DL High ms", "dl_high_ms"), ("Jitter ms", "jitter_ms")]:
            b = statistics.median(getattr(s, attr) for s in ok_before)
            a = statistics.median(getattr(s, attr) for s in ok_after)
            print(f"    {label:<20} {b:>10.1f} {a:>10.1f} {a - b:>+10.1f}")


def print_cliff(cliff: dict) -> None:
    print_section("CLIFF TEST (one-byte boundary)")
    if not cliff.get("valid", True):
        print(f"  SKIPPED: {cliff.get('error', 'unknown reason')}")
        return
    for label in ("at_limit", "over_limit"):
        r = cliff[label]
        expected = r["packet_loss_pct"] == (0 if label == "at_limit" else 100)
        tag = "PASS (expected)" if expected else "UNEXPECTED"
        print(f"  {label}: {r['total_bytes']} B total -> {r['packet_loss_pct']}% loss  [{tag}]")


def measure_load(host: str, args: argparse.Namespace, phase: PhaseResult) -> None:
    print(f"\n  Running {args.speedtest_runs} speedtests (watching frag counters)...")
    for i in range(1, args.speedtest_runs + 1):
        before = read_frag_counters(host)
        print(f"    run {i}/{args.speedtest_runs}...", end=" ", flush=True)
        st = run_speedtest(host, args.speedtest_cmd)
        delta = read_frag_counters(host) - before
        phase.speedtests.append(st)
        phase.frag_deltas.append(delta)
        frag_note = f"ReasmReqds+{delta.reasm_reqds}" if delta.reasm_reqds else "no reassembly"
        if st.error:
            dl_note = f"ERROR: {st.error}"
        else:
            dl_note = f"IQM={st.dl_iqm_ms:.1f}ms  high={st.dl_high_ms:.1f}ms  jitter={st.jitter_ms:.1f}ms"
        print(f"{dl_note}  [{frag_note}]")


def main() -> None:
    parser = argparse.ArgumentParser(description="tunnelmtu MTU fix validation")
    parser.add_argument("--host", required=True,
                        help="SSH target running tunnelmtu (e.g. root@10.0.0.240)")
    parser.add_argument("--interfaces", required=True,
                        help="Comma-separated interface list (e.g. l2tpeth0,l2tpeth1)")
    parser.add_argument("--target", default="1.1.1.1",
                        help="Probe target IP (default: 1.1.1.1)")
    parser.add_argument("--speedtest-cmd", default="speedtest -f jsonl",
                        help="Speedtest command on the host; must print a JSONL result line "
                             "(default: 'speedtest -f jsonl')")
    parser.add_argument("--speedtest-runs", type=int, default=5,
                        help="Speedtest runs per phase (default: 5)")
    parser.add_argument("--skip-cliff", action="store_true",
                        help="Skip the one-byte MTU boundary (cliff) test")
    args = parser.parse_args()

    host = args.host
    ifaces = [i.strip() for i in args.interfaces.split(",")]
    target = args.target

    print("tunnelmtu MTU Validation Test Plan")
    print(f"Host:       {host}")
    print(f"Interfaces: {', '.join(ifaces)}")
    print(f"Target:     {target}")
    print(f"Time:       {datetime.now(UTC).isoformat()}")
    print(f"Runs:       {args.speedtest_runs} speedtests per phase")

    print_section("PHASE 1: Baseline (MTU 1500, expected fragmentation)")

    print("  Checking interfaces are at MTU 1500...")
    bad = []
    for iface in ifaces:
        actual = get_iface_mtu(host, iface)
        status = "OK" if actual == 1500 else f"WRONG, got {actual}"
        print(f"    {iface}: {actual} B  [{status}]")
        if actual != 1500:
            bad.append(iface)
    if bad:
        raise RuntimeError(
            f"Interface(s) {', '.join(bad)} are not at MTU 1500. "
            f"Set them on both tunnel ends and re-run."
        )

    phase1 = PhaseResult(name="Phase 1: MTU 1500 (broken)", configured_mtu=1500)

    print("\n  Running tunnelmtu sweep...")
    for iface in ifaces:
        print(f"    {iface}...", end=" ", flush=True)
        w = run_tunnelmtu(host, iface, target)
        phase1.tunnelmtu.append(w)
        print(f"usable={w.usable_mtu}  path={w.path_mtu}  [{status_of(w)}]")

    measure_load(host, args, phase1)

    print_section("PHASE 2: Applying MTU fix")

    usable_mtus = [w.usable_mtu for w in phase1.tunnelmtu if w.usable_mtu > 0]
    if not usable_mtus:
        raise RuntimeError("tunnelmtu returned no usable MTU for any interface, cannot apply fix")

    # Take the minimum across interfaces
    correct_mtu = min(usable_mtus)

    print("\n  ACTION REQUIRED")
    print(f"  Set MTU to {correct_mtu} B on BOTH ends of the tunnel.")
    print("  Type 'yes' when both ends are set and ready: ", end="", flush=True)

    response = input().strip().lower()
    while response != "yes":
        print("  Type 'yes' when ready: ", end="", flush=True)
        response = input().strip().lower()

    print()
    for iface in ifaces:
        actual = get_iface_mtu(host, iface)
        match = "OK" if actual == correct_mtu else f"MISMATCH, expected {correct_mtu}, got {actual}"
        print(f"  {iface} MTU: {actual} B  [{match}]")

    print("\n  Re-running tunnelmtu to confirm no warning...")
    phase2_checks = []
    for idx, iface in enumerate(ifaces):
        print(f"    {iface}...", end=" ", flush=True)
        keep = not args.skip_cliff and (idx == len(ifaces) - 1)
        w = run_tunnelmtu(host, iface, target, keep_netns=keep)
        phase2_checks.append(w)
        suffix = "  [netns kept for cliff test]" if keep else ""
        print(f"usable={w.usable_mtu}  configured={w.configured_mtu}  [{status_of(w)}]{suffix}")

    print_section("PHASE 3: After fix (MTU corrected)")

    phase3 = PhaseResult(name="Phase 3: MTU corrected", configured_mtu=correct_mtu)
    phase3.tunnelmtu = phase2_checks
    measure_load(host, args, phase3)

    cliff: dict = {}
    if not args.skip_cliff:
        print_section("PHASE 4: Cliff test (one-byte MTU boundary)")
        print(f"  Testing at {correct_mtu} B (pass) and {correct_mtu + 1} B (fail)...")
        cliff = ping_boundary(host, target, correct_mtu)
        print_cliff(cliff)
        ssh(host, "ip netns delete tunnelmtu 2>/dev/null || true", check=False)

    print_section("FINAL REPORT")
    print_phase(phase1)
    print_phase(phase3)
    print_comparison(phase1, phase3)

    report = {
        "host": host,
        "interfaces": ifaces,
        "target": target,
        "timestamp": datetime.now(UTC).isoformat(),
        "phase1": {
            "configured_mtu": phase1.configured_mtu,
            "tunnelmtu": [_as_dict(w) for w in phase1.tunnelmtu],
            "speedtests": [_as_dict(s) for s in phase1.speedtests],
            "frag_deltas": [vars(d) for d in phase1.frag_deltas],
        },
        "correct_mtu": correct_mtu,
        "phase3": {
            "configured_mtu": phase3.configured_mtu,
            "tunnelmtu": [_as_dict(w) for w in phase3.tunnelmtu],
            "speedtests": [_as_dict(s) for s in phase3.speedtests],
            "frag_deltas": [vars(d) for d in phase3.frag_deltas],
        },
        "cliff_test": cliff,
    }
    outfile = f"tunnelmtu_test_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
    with open(outfile, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Raw results saved to: {outfile}")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)
