package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// overheadLayer describes one encapsulation header consuming MTU.
type overheadLayer struct {
	Label string `json:"label"`
	Bytes int    `json:"bytes"`
}

type ifaceInfo struct {
	Name     string `json:"ifname"`
	LinkType string `json:"link_type"`
	MTU      int    `json:"mtu"`
}

type MTUResult struct {
	Interface     string          `json:"interface"`
	LinkType      string          `json:"link_type"`
	Target        string          `json:"target"`
	ConfiguredMTU int             `json:"configured_mtu"`
	PathMTU       int             `json:"path_mtu"`
	Overhead      []overheadLayer `json:"overhead,omitempty"`
	TotalOverhead int             `json:"total_overhead"`
	UsableMTU     int             `json:"usable_mtu"`
	ProbeCount    int             `json:"probe_count"`
	DurationMs    int64           `json:"duration_ms"`
	Pass          *bool           `json:"pass,omitempty"`
	ErrMsg        string          `json:"error,omitempty"`
}

const (
	mtuNS     = "tunnelmtu"
	mtuVethR  = mtuNS + "-root"
	mtuVethNS = mtuNS + "-ns"
	mtuRootIP = "169.254.9.1/24"
	mtuNSIP   = "169.254.9.2/24"
	mtuNSSrc  = "169.254.9.2"

	icmpv4Overhead = 28 // IPv4 header (20) + ICMP header (8)
)

func run(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w — %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runOut(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

func runInNS(args ...string) error {
	return run("ip", append([]string{"netns", "exec", mtuNS}, args...)...)
}

func destroyMTUNS() {
	if out, _ := runOut("sh", "-c",
		fmt.Sprintf("ip rule show all | grep 'iif %s' | cut -d: -f1 | head -n1", mtuVethR)); out != "" {
		_ = run("ip", "rule", "del", "prio", out)
	}
	_ = run("sh", "-c",
		"iptables -t nat -S POSTROUTING | grep '169.254.9.2' | sed 's/^-A/-D/' | xargs -r -L1 iptables -t nat")
	_ = run("ip", "link", "set", mtuVethR, "down")
	_ = runInNS("ip", "link", "set", mtuVethNS, "down")
	_ = run("ip", "link", "delete", mtuVethR)
	_ = run("ip", "netns", "delete", mtuNS)
}

func buildMTUNS() error {
	destroyMTUNS()

	if err := run("ip", "netns", "add", mtuNS); err != nil {
		return err
	}
	if err := run("ip", "link", "add", mtuVethR, "type", "veth", "peer", "name", mtuVethNS); err != nil {
		return err
	}
	if err := run("ip", "link", "set", mtuVethNS, "netns", mtuNS); err != nil {
		return err
	}
	if err := run("ip", "addr", "add", mtuRootIP, "dev", mtuVethR); err != nil {
		return err
	}
	if err := run("ip", "link", "set", mtuVethR, "up"); err != nil {
		return err
	}

	time.Sleep(200 * time.Millisecond)

	if err := runInNS("ip", "addr", "add", mtuNSIP, "dev", mtuVethNS); err != nil {
		return err
	}
	if err := runInNS("ip", "link", "set", mtuVethNS, "up"); err != nil {
		return err
	}
	if err := runInNS("ip", "link", "set", "lo", "up"); err != nil {
		return err
	}
	return runInNS("ip", "route", "add", "default", "via", "169.254.9.1")
}

func resolveCustIP() (string, error) {
	custInt, _ := runOut("sh", "-c",
		"ip route show | grep -v dhcp | grep -v l2tp | grep -v '169.254.' | awk '{print $3}' | tail -n1")
	if custInt == "" {
		return "", fmt.Errorf("could not determine customer interface from routing table")
	}
	custIP, _ := runOut("sh", "-c",
		fmt.Sprintf("ip neigh show dev %s | awk 'NR==1{print $1}'", custInt))
	if custIP == "" {
		return "", fmt.Errorf("no neighbour found on %s", custInt)
	}
	return custIP, nil
}

var l2tpOverhead = []overheadLayer{
	{"IPv4 header", 20},
	{"UDP header", 8},
	{"L2TPv3 header", 8},
	{"Inner Ethernet", 14},
}

// Sends a single DF bit ICMP of totalBytes, returns true if no frag.
func probeMTU(target, iface string, totalBytes int) (bool, error) {
	payloadBytes := totalBytes - icmpv4Overhead
	if payloadBytes < 0 {
		payloadBytes = 0
	}
	pingArgs := []string{"-M", "do", "-c", "1", "-W", "2", "-s", strconv.Itoa(payloadBytes)}

	var err error
	if strings.HasPrefix(iface, "l2tpeth") {
		// Probe runs inside tunnelmtu; routing is handled by the iif policy rule.
		err = runInNS(append([]string{"ping"}, append(pingArgs, target)...)...)
	} else {
		if iface != "" {
			pingArgs = append(pingArgs, "-I", iface)
		}
		err = exec.Command("ping", append(pingArgs, target)...).Run()
	}

	if err != nil {
		return false, nil //nolint:nilerr // non-zero exit means probe was too large
	}
	return true, nil
}

// binary-searches for the largest IP datagram that passes a DF probe.
func sweepMTU(target, iface string, minSize, maxSize int) (mtu, probes int, err error) {
	lo, hi := minSize, maxSize

	ok, err := probeMTU(target, iface, lo)
	if err != nil {
		return 0, 1, err
	}
	if !ok {
		return 0, 1, fmt.Errorf("probe failed at minimum size %d — check connectivity to %s", lo, target)
	}

	probes = 1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		ok, err = probeMTU(target, iface, mid)
		if err != nil {
			return 0, probes, err
		}
		probes++
		if ok {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo, probes, nil
}

func sweepL2TP(iface ifaceInfo, target string, minSize, maxSize int, verbose, keepNetns bool) MTUResult {
	result := MTUResult{Interface: iface.Name, LinkType: iface.LinkType, Target: target, ConfiguredMTU: iface.MTU}

	custIP, err := resolveCustIP()
	if err != nil {
		result.ErrMsg = fmt.Sprintf("resolveCustIP: %s", err)
		return result
	}

	if err := buildMTUNS(); err != nil {
		result.ErrMsg = fmt.Sprintf("buildMTUNS: %s", err)
		return result
	}
	cleanup := destroyMTUNS
	if keepNetns {
		cleanup = func() {}
	}
	defer cleanup()

	// Steer packets from the veth directly into the tunnel's routing table
	table := "tunnel_routes_" + iface.Name
	if err := run("ip", "rule", "add", "from", "all", "iif", mtuVethR, "lookup", table); err != nil {
		result.ErrMsg = fmt.Sprintf("ip rule add: %s", err)
		return result
	}

	// SNAT to the customer IP so the tunnel gateway can route replies back
	if err := run("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", mtuNSSrc, "-j", "SNAT", "--to", custIP); err != nil {
		result.ErrMsg = fmt.Sprintf("iptables SNAT: %s", err)
		return result
	}

	if verbose {
		fmt.Printf("[debug] custIP: %s  table: %s\n", custIP, table)
		rules, _ := runOut("ip", "rule", "show")
		fmt.Printf("[debug] ip rule show:\n%s\n", rules)
		routes, _ := runOut("ip", "route", "show", "table", table)
		fmt.Printf("[debug] ip route show table %s:\n%s\n", table, routes)
		nat, _ := runOut("iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "--line-numbers")
		fmt.Printf("[debug] iptables nat POSTROUTING:\n%s\n", nat)
		gwOk := runInNS("ping", "-c", "1", "-W", "1", "169.254.9.1")
		fmt.Printf("[debug] ping 169.254.9.1 from netns: err=%v\n", gwOk)
		extOk := runInNS("ping", "-c", "1", "-W", "2", target)
		fmt.Printf("[debug] ping %s from netns: err=%v\n", target, extOk)
	}

	overhead := l2tpOverhead
	total := 0
	for _, l := range overhead {
		total += l.Bytes
	}

	start := time.Now()
	mtu, probes, err := sweepMTU(target, iface.Name, minSize, maxSize)
	result.ProbeCount = probes
	result.DurationMs = time.Since(start).Milliseconds()

	if err != nil {
		result.ErrMsg = err.Error()
		return result
	}

	result.PathMTU = mtu + total // outer frame size (inner probe + encapsulation)
	result.Overhead = overhead
	result.TotalOverhead = total
	result.UsableMTU = mtu // inner probe result already accounts for overhead
	pass := result.UsableMTU >= 1430
	result.Pass = &pass
	return result
}

func printResult(r MTUResult, w io.Writer) {
	fmt.Fprintf(w, "Interface:  %s  (%s)\n", r.Interface, r.LinkType)
	fmt.Fprintf(w, "Target:     %s\n", r.Target)

	if r.ErrMsg != "" || r.PathMTU == 0 {
		msg := r.ErrMsg
		if msg == "" {
			msg = "probe failed"
		}
		fmt.Fprintf(w, "  ERROR: %s\n", msg)
		return
	}

	fmt.Fprintf(w, "Path MTU:   %d bytes\n", r.PathMTU)
	if len(r.Overhead) > 0 {
		fmt.Fprintf(w, "Overhead:\n")
		for _, l := range r.Overhead {
			fmt.Fprintf(w, "  %-20s %3d B\n", l.Label, l.Bytes)
		}
		fmt.Fprintf(w, "  %-20s %3d B\n", "Total overhead", r.TotalOverhead)
	}
	fmt.Fprintf(w, "Configured: %d bytes\n", r.ConfiguredMTU)
	fmt.Fprintf(w, "Usable MTU: %d bytes\n", r.UsableMTU)
	if r.ConfiguredMTU != 0 {
		if r.ConfiguredMTU > r.UsableMTU {
			fmt.Fprintf(w, "  WARN: interface MTU too high, set to %d to prevent fragmentation\n", r.UsableMTU)
		} else if r.ConfiguredMTU < r.UsableMTU {
			fmt.Fprintf(w, "  WARN: interface MTU too low, set to %d to recover throughput\n", r.UsableMTU)
		} else if r.UsableMTU < 1430 {
			fmt.Fprintf(w, "  WARN: interface MTU may be capping the probe; raise it and re-run to find true path capacity\n")
		}
	}
	if r.Pass != nil {
		if *r.Pass {
			fmt.Fprintf(w, "Status:     PASS\n")
		} else {
			fmt.Fprintf(w, "Status:     WARN: usable MTU %d < 1430, fragmentation likely\n", r.UsableMTU)
		}
	}
	fmt.Fprintf(w, "Probes:     %d  (%d ms)\n", r.ProbeCount, r.DurationMs)
}

// MTUCmd returns the mtu subcommand.
func MTUCmd() *cobra.Command {
	var (
		minSize   int
		maxSize   int
		iface     string
		jsonOut   bool
		verbose   bool
		keepNetns bool
	)

	cmd := &cobra.Command{
		Use:          "mtu -i <interface> <target>",
		Short:        "Sweep path MTU to a target using ICMP DF probes",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if iface == "" {
				return fmt.Errorf("--interface / -i is required")
			}
			target := args[0]

			out, err := exec.Command("ip", "-j", "link", "show", iface).CombinedOutput()
			if err != nil {
				return fmt.Errorf("interface %s not found: %s", iface, strings.TrimSpace(string(out)))
			}
			var parsed []ifaceInfo
			if err := json.Unmarshal(out, &parsed); err != nil || len(parsed) == 0 {
				return fmt.Errorf("could not parse interface info for %s", iface)
			}
			i := parsed[0]

			var r MTUResult
			if strings.HasPrefix(i.Name, "l2tpeth") {
				r = sweepL2TP(i, target, minSize, maxSize, verbose, keepNetns)
			} else {
				r = MTUResult{Interface: i.Name, LinkType: i.LinkType, Target: target, ConfiguredMTU: i.MTU}
				start := time.Now()
				mtu, probes, sweepErr := sweepMTU(target, i.Name, minSize, maxSize)
				r.ProbeCount = probes
				r.DurationMs = time.Since(start).Milliseconds()
				if sweepErr != nil {
					r.ErrMsg = sweepErr.Error()
				} else {
					r.PathMTU = mtu
					r.UsableMTU = mtu
				}
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(r)
			}

			printResult(r, cmd.OutOrStdout())

			if r.ErrMsg != "" || (r.Pass != nil && !*r.Pass) {
				return fmt.Errorf("mtu check failed or warned")
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&minSize, "min", 576, "minimum probe size in bytes (total IP datagram)")
	cmd.Flags().IntVar(&maxSize, "max", 1500, "maximum probe size in bytes (total IP datagram)")
	cmd.Flags().StringVarP(&iface, "interface", "i", "", "interface to probe (required)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output results as JSON")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print debug info during l2tpeth sweeps")
	cmd.Flags().BoolVar(&keepNetns, "keep-netns", false, "leave the netns alive after sweep")

	return cmd
}
