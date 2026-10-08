// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/dataexchange"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
	acceptpkg "github.com/pilot-protocol/rendezvous/accept"
	pluginsruntime "github.com/pilot-protocol/runtime"
)

// TestSoakSwarmAgentMemory reproduces the service-agent memory growth: one
// agent daemon (a separate process started from PILOT_SOAK_AGENT_BIN with
// the fleet's flags and -pprof) serves a churning swarm of short-lived
// clients. Each client trust-handshakes, sends a message, and gets a reply
// the way the fleet's responder sends one (handshake, then a dial back to
// port 1001). Some clients stay up and idle for the whole run, some register
// an endpoint nobody listens on so the agent reaches them over the relay.
//
// Every PILOT_SOAK_SAMPLE the test records the agent's live heap (after a
// forced GC), goroutines, RSS, peers and connections, and at the end saves
// a heap profile and a goroutine dump next to PILOT_SOAK_OUT. Off unless
// PILOT_SOAK_AGENT_BIN is set. Knobs (environment):
//
//	PILOT_SOAK_DURATION        run length (20m)
//	PILOT_SOAK_STOP_NEW_AFTER  no new clients after this (the duration); the
//	                           rest of the run shows what the agent releases
//	PILOT_SOAK_RATE            new clients per second (2)
//	PILOT_SOAK_LIFETIME        how long a client stays up (90s)
//	PILOT_SOAK_STAY_FRACTION   clients that stay up, idle, all run (0.15)
//	PILOT_SOAK_RELAY_FRACTION  clients the agent must reach by relay (0.5)
//	PILOT_SOAK_SWARM_IDLE_AFTER  the clients' PeerIdleAfter; 0 keeps their
//	                           sessions warm forever like older daemons
//	PILOT_SOAK_AGENT_GODEBUG   GODEBUG for the agent, e.g. memprofilerate=4096
//
//	go build -o /tmp/agent ./cmd/daemon
//	PILOT_SOAK_AGENT_BIN=/tmp/agent PILOT_SOAK_OUT=/tmp/soak.csv \
//	  go test ./tests -run TestSoakSwarmAgentMemory -timeout 0 -v
func TestSoakSwarmAgentMemory(t *testing.T) {
	bin := os.Getenv("PILOT_SOAK_AGENT_BIN")
	if bin == "" {
		t.Skip("set PILOT_SOAK_AGENT_BIN to an agent daemon binary built with -pprof")
	}
	dur := soakDuration("PILOT_SOAK_DURATION", 20*time.Minute)
	sample := soakDuration("PILOT_SOAK_SAMPLE", 30*time.Second)
	lifetime := soakDuration("PILOT_SOAK_LIFETIME", 90*time.Second)
	ratePerSec := soakFloat("PILOT_SOAK_RATE", 2)
	stayFrac := soakFloat("PILOT_SOAK_STAY_FRACTION", 0.15)
	relayFrac := soakFloat("PILOT_SOAK_RELAY_FRACTION", 0.5)
	stopNew := soakDuration("PILOT_SOAK_STOP_NEW_AFTER", dur) // churn stops here; the rest shows what is released
	outPath := os.Getenv("PILOT_SOAK_OUT")

	home, err := os.MkdirTemp("/tmp", "soak-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	// The in-process swarm's plugins write under $HOME/.pilot; keep them off
	// the real one.
	t.Setenv("HOME", filepath.Join(home, "swarm-home"))
	daemon.TunnelKeepaliveInterval = 25 * time.Second
	// The swarm runs this tree's daemon code. PILOT_SOAK_SWARM_IDLE_AFTER=0
	// keeps its sessions warm forever, as clients before the idle-peer
	// change do; the default lets them fall silent when idle, as the
	// fleet's v1.8.0 swarm does (it has no per-peer keepalive at all).
	if v := os.Getenv("PILOT_SOAK_SWARM_IDLE_AFTER"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			daemon.PeerIdleAfter = d
		}
	}

	env := NewTestEnv(t)
	// Every swarm node reaches the registry from 127.0.0.1; without this
	// the per-IP and global request caps throttle the swarm, not the agent.
	if err := env.Registry.SetRateLimitWhitelist([]acceptpkg.WhitelistEntry{{CIDR: "127.0.0.0/8", Rate: 1 << 20}}); err != nil {
		t.Fatal(err)
	}

	// --- agent process -------------------------------------------------
	agentHome := filepath.Join(home, "agent-home")
	if err := os.MkdirAll(agentHome, 0o700); err != nil {
		t.Fatal(err)
	}
	agentSock := filepath.Join(home, "agent.sock")
	pprofPort := freeTCPPort(t)
	pprofAddr := fmt.Sprintf("127.0.0.1:%d", pprofPort)
	logf, err := os.Create(filepath.Join(home, "agent.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin,
		"-registry", env.RegistryAddr, "-beacon", env.BeaconAddr,
		"-listen", "127.0.0.1:0", "-socket", agentSock,
		"-identity", filepath.Join(agentHome, "identity.json"),
		"-hostname", "soak-agent", "-email", "soak@pilot.local",
		"-encrypt", "-public", "-trust-auto-approve",
		"-idle-timeout", "3600s", "-keepalive", "300s",
		"-no-skillinject", "-motd-feed-url", "", "-telemetry-url", "",
		"-pprof", pprofAddr,
	)
	cmd.Env = append(os.Environ(), "HOME="+agentHome)
	if g := os.Getenv("PILOT_SOAK_AGENT_GODEBUG"); g != "" {
		cmd.Env = append(cmd.Env, "GODEBUG="+g) // e.g. memprofilerate=1 for an exact heap profile
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
		}
		logf.Close()
		if outPath != "" {
			_ = copyFile(filepath.Join(home, "agent.log"), outPath+".agent.log")
		}
	})
	var agentDrv *driver.Driver
	deadline := time.Now().Add(30 * time.Second)
	for {
		agentDrv, err = driver.Connect(agentSock)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent socket: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	defer agentDrv.Close()
	var agentNode uint32
	for {
		info, err := agentDrv.Info()
		if err == nil {
			if v, ok := info["node_id"].(float64); ok && v > 0 {
				agentNode = uint32(v)
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent never registered: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	agentAddr := protocol.Addr{Network: 0, Node: agentNode}
	t.Logf("agent node %d pid %d pprof %s", agentNode, cmd.Process.Pid, pprofAddr)

	// --- responder: what pilot-agents/deploy/responder.py does ----------
	type replyTo struct{ addr protocol.Addr }
	replyCh := make(chan replyTo, 4096)
	var repliesOK, repliesFail, sendsOK, sendsFail, started, stopped atomic.Int64
	var respWG sync.WaitGroup
	for i := 0; i < 8; i++ {
		respWG.Add(1)
		go func() {
			defer respWG.Done()
			for r := range replyCh {
				_, _ = agentDrv.Handshake(r.addr.Node, "reply")
				c, err := dataexchange.Dial(agentDrv, r.addr)
				if err != nil {
					repliesFail.Add(1)
					continue
				}
				if err := c.SendText("reply"); err != nil {
					repliesFail.Add(1)
				} else {
					repliesOK.Add(1)
				}
				c.Close()
			}
		}()
	}
	inbox := filepath.Join(agentHome, ".pilot", "inbox")
	stopInboxSweep := make(chan struct{})
	go func() {
		tk := time.NewTicker(5 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-stopInboxSweep:
				return
			case <-tk.C:
				ents, _ := os.ReadDir(inbox)
				for _, e := range ents {
					_ = os.Remove(filepath.Join(inbox, e.Name()))
				}
			}
		}
	}()

	// --- swarm -----------------------------------------------------------
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()
	var swarmWG sync.WaitGroup
	var alive atomic.Int64
	idx := 0
	stopNewAt := time.Now().Add(stopNew)
	go func() {
		interval := time.Duration(float64(time.Second) / ratePerSec)
		tk := time.NewTicker(interval)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
			}
			if time.Now().After(stopNewAt) {
				continue
			}
			idx++
			n := idx
			stay := float64(n%100) < stayFrac*100
			relay := float64((n/7)%100) < relayFrac*100
			swarmWG.Add(1)
			go func() {
				defer swarmWG.Done()
				sn, err := startSoakSwarmNode(env, home, n, relay)
				if err != nil {
					t.Logf("swarm %d: %v", n, err)
					return
				}
				started.Add(1)
				alive.Add(1)
				defer func() {
					sn.stop()
					alive.Add(-1)
					stopped.Add(1)
				}()
				_, _ = sn.drv.Handshake(agentNode, "soak")
				c, err := dataexchange.Dial(sn.drv, agentAddr)
				if err != nil {
					sendsFail.Add(1)
				} else {
					if err := c.SendText(fmt.Sprintf("query %d", n)); err != nil {
						sendsFail.Add(1)
					} else {
						sendsOK.Add(1)
						select {
						case replyCh <- replyTo{sn.d.Addr()}:
						default:
						}
					}
					c.Close()
				}
				life := lifetime
				if stay {
					life = dur
				}
				select {
				case <-ctx.Done():
				case <-time.After(life):
				}
			}()
		}
	}()

	// --- sampler ---------------------------------------------------------
	var out *os.File
	if outPath != "" {
		out, err = os.Create(outPath)
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		fmt.Fprintln(out, "elapsed_s,heap_alloc_mb,heap_inuse_mb,heap_objects,goroutines,rss_mb,peers,relay_peers,encrypted_peers,conns,swarm_started,swarm_alive,sends_ok,sends_fail,replies_ok,replies_fail")
	}
	start := time.Now()
	dumpedGoroutines := false
	peakRSS := 0.0
	takeSample := func() {
		ms := pprofMemStats(pprofAddr)
		gr := pprofGoroutines(pprofAddr)
		rss := processRSSMB(cmd.Process.Pid)
		if outPath != "" && gr > 2000 && !dumpedGoroutines {
			// A pile-up: keep its stacks.
			dumpedGoroutines = true
			_ = fetchToFile("http://"+pprofAddr+"/debug/pprof/goroutine?debug=1", outPath+".goroutines-pileup.txt")
		}
		if outPath != "" && rss > peakRSS {
			peakRSS = rss
			_ = fetchToFile("http://"+pprofAddr+"/debug/pprof/heap", outPath+".heap-peak.pb.gz")
		}
		h, _ := agentDrv.Health()
		num := func(k string) int64 {
			if v, ok := h[k].(float64); ok {
				return int64(v)
			}
			return -1
		}
		line := fmt.Sprintf("%d,%.1f,%.1f,%d,%d,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
			int(time.Since(start).Seconds()), float64(ms["HeapAlloc"])/1e6, float64(ms["HeapInuse"])/1e6, ms["HeapObjects"],
			gr, rss, num("peers"), num("relay_peer_count"), num("encrypted_peers"), num("connections"),
			started.Load(), alive.Load(), sendsOK.Load(), sendsFail.Load(), repliesOK.Load(), repliesFail.Load())
		t.Log(line)
		if out != nil {
			fmt.Fprintln(out, line)
		}
	}
	tk := time.NewTicker(sample)
	defer tk.Stop()
	takeSample()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-tk.C:
			takeSample()
		}
	}
	takeSample()
	if outPath != "" {
		_ = fetchToFile("http://"+pprofAddr+"/debug/pprof/heap?gc=1", outPath+".heap.pb.gz")
		_ = fetchToFile("http://"+pprofAddr+"/debug/pprof/goroutine?debug=1", outPath+".goroutines.txt")
	}
	cancel()
	swarmWG.Wait()
	close(replyCh)
	respWG.Wait()
	close(stopInboxSweep)
}

type soakSwarmNode struct {
	d   *daemon.Daemon
	rt  *pluginsruntime.Runtime
	drv *driver.Driver
}

func (s *soakSwarmNode) stop() {
	s.drv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = s.rt.StopPlugins(ctx)
	cancel()
	_ = s.d.Stop()
}

// startSoakSwarmNode starts one swarm client. With relay set it registers an
// endpoint nothing listens on, so the agent's direct sends fail and it falls
// back to the beacon relay, as it does for the fleet's NATed clients.
func startSoakSwarmNode(env *TestEnv, dir string, n int, relay bool) (*soakSwarmNode, error) {
	sock := filepath.Join(dir, fmt.Sprintf("s%d.sock", n))
	cfg := daemon.Config{
		RegistryAddr:        env.RegistryAddr,
		BeaconAddr:          env.BeaconAddr,
		ListenAddr:          "127.0.0.1:0",
		SocketPath:          sock,
		IdentityPath:        filepath.Join(dir, fmt.Sprintf("s%d.json", n)),
		Email:               fmt.Sprintf("swarm-%d@pilot.local", n),
		Encrypt:             true,
		TrustAutoApprove:    true,
		DisableEventStream:  true,
		DisablePolicyRunner: true,
	}
	if relay {
		cfg.Endpoint = "127.0.0.1:9"
	}
	d := daemon.New(cfg)
	rt := registerStandardPlugins(soakFatal{}, d, &cfg)
	if err := rt.StartPlugins(context.Background()); err != nil {
		return nil, err
	}
	if err := d.Start(); err != nil {
		return nil, err
	}
	drv, err := driver.Connect(sock)
	if err != nil {
		_ = d.Stop()
		return nil, err
	}
	return &soakSwarmNode{d: d, rt: rt, drv: drv}, nil
}

type soakFatal struct{}

func (soakFatal) Fatalf(format string, args ...interface{}) { panic(fmt.Sprintf(format, args...)) }

func soakDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func soakFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func freeTCPPort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

var memStatLine = regexp.MustCompile(`^# (\w+) = (\d+)`)

// pprofMemStats reads runtime.MemStats from the heap profile's debug text,
// after the forced GC that gc=1 asks for.
func pprofMemStats(addr string) map[string]int64 {
	out := map[string]int64{}
	resp, err := http.Get("http://" + addr + "/debug/pprof/heap?gc=1&debug=1")
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		if m := memStatLine.FindStringSubmatch(sc.Text()); m != nil {
			v, _ := strconv.ParseInt(m[2], 10, 64)
			out[m[1]] = v
		}
	}
	return out
}

func pprofGoroutines(addr string) int64 {
	resp, err := http.Get("http://" + addr + "/debug/pprof/goroutine?debug=1")
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	line, _ := bufio.NewReader(resp.Body).ReadString('\n')
	f := strings.Fields(line) // "goroutine profile: total N"
	if len(f) == 0 {
		return -1
	}
	n, _ := strconv.ParseInt(f[len(f)-1], 10, 64)
	return n
}

func processRSSMB(pid int) float64 {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return -1
	}
	kb, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	return kb / 1024
}

func fetchToFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}
