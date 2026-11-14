# tunnelmtu

Tunnel diagnostics CLI for tracking silent fragmentation, MTU mismatches, and encapsulation overhead on L2TPv3 circuits.

## Note

This was built at a previous job for a specific L2TPv3-over-fixed-wireless deployment on embedded Linux routers. It will not run as-is against a generic network. It shells out to `ip`, `iptables`, and `ping`, assumes policy-routing tables named `tunnel_routes_<iface>`, and expects a customer facing interface it can discover from the main routing table.

## The problem

When using fixed wireless links (FWAC) every tunnel spends bytes on encapsulation when using L2TP. If the tunnel interface is left at 1500 MTU on a path that can't carry 1500 bytes plus the overhead from the tunnel, full size packets get fragmented by the underlay. The only evidence of this is the Linux kernel's fragmentation counters found in `/proc/net/snmp`. tunnelmtu finds the largest packet that will make it through the tunnel and tells the user what the interface MTU should be. That is the most efficient packet size for the path, but it can still be fragmented on carrier links and transit networks outside our control. 

## Usage

```
tunnelmtu mtu -i <interface> <target> [flags]

Flags:
  -i, --interface string   interface to probe (required)
      --json               output results as JSON
      --keep-netns         leave the netns alive after sweep
      --max int            maximum probe size in bytes (total IP datagram) (default 1500)
      --min int            minimum probe size in bytes (total IP datagram) (default 576)
  -v, --verbose            print debug info during l2tpeth sweeps
```

Example, from the baseline run in the reports below:

```
$ tunnelmtu mtu -i l2tpeth1003 1.1.1.1

Interface:  l2tpeth1003  (ether)
Target:     1.1.1.1
Path MTU:   1488 bytes
Overhead:
  IPv4 header           20 B
  UDP header             8 B
  L2TPv3 header          8 B
  Inner Ethernet        14 B
  Total overhead        50 B
Configured: 1500 bytes
Usable MTU: 1438 bytes
  WARN: interface MTU too high, set to 1438 to prevent fragmentation
Status:     PASS
Probes:     11  (4948 ms)
```

| Field | Meaning |
|---|---|
| Path MTU | Largest outer packet the underlay carries (usable MTU + overhead) |
| Overhead | Per-layer L2TPv3 encapsulation cost |
| Configured | Current interface MTU |
| Usable MTU | Largest inner IP datagram that gets through. Set the interface MTU to this. |
| Status | PASS if the usable MTU is at least 1430, WARN otherwise |

Status describes the path. The configured MTU is checked separately:

| Warning | Cause | Action |
|---|---|---|
| Interface MTU too high | Packets exceed path capacity and get fragmented | `ip link set <iface> mtu <usable>` on both ends |
| Interface MTU too low | Throughput left on the table | `ip link set <iface> mtu <usable>` on both ends |
| Interface MTU may be capping the probe | Configured MTU equals the result and is below 1430, so true path capacity is unknown | Raise the interface MTU and re-run |

### L2TPv3 overhead

```
IPv4 (20) + UDP (8) + L2TPv3 (8) + inner Ethernet (14) = 50 bytes
```

On a path that carries 1488-byte outer packets, inner traffic can use at most 1438 bytes.

## Results

Two test runs, each covering both production L2TPv3 tunnels (`l2tpeth1002` and `l2tpeth1003`), all starting at MTU 1500. The tighter tunnel (`l2tpeth1003`) had a usable MTU of 1438, which was then set on both tunnels since they work in tandem for load balancing and QoS. The raw reports are [tunnelmtu_test_20260317_175035.json](tunnelmtu_test_20260317_175035.json) and [tunnelmtu_test_20260317_182004.json](tunnelmtu_test_20260317_182004.json). They were created by [test_mtu.py](test_mtu.py), which was run on a customer CPE to test the accuracy of the tool.

| Fragmented packets during speedtests | Before (MTU 1500) | After (MTU 1438) |
|---|---|---|
| Run 1 (5 speedtests) | 149 | 0 |
| Run 2 (10 speedtests) | 294 | 0 |
