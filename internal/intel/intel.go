// Package intel — Threat intelligence registry.
// Holds curated indicators (JA3 fingerprints, scanner UA strings, IP blocklists,
// attack-signature patterns) used by static analysers, plus runtime counters and
// a user-managed block list.
package intel

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Indicator is a single IOC entry.
type Indicator struct {
	ID          string    `json:"id"`
	Family      string    `json:"family"`
	Category    string    `json:"category"` // ja3 | scanner | signature | dns
	Value       string    `json:"value"`
	Severity    string    `json:"severity"`
	Description string    `json:"description,omitempty"`
	Hits        uint64    `json:"hits"`
	LastHit     time.Time `json:"last_hit,omitempty"`
}

// BlockedIP is a user- or auto-added block entry.
type BlockedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	AddedAt   time.Time `json:"added_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	AutoAdded bool      `json:"auto"`
}

// Registry stores IOCs and maintains runtime hit counters.
type Registry struct {
	mu      sync.RWMutex
	ind     map[string]*Indicator // keyed by ID
	blocks  map[string]*BlockedIP // keyed by IP
	feedDir string
}

// NewRegistry returns a registry pre-populated with built-in JA3 fingerprints
// and scanner user-agents. If feedDir is non-empty, loads extra *.txt feeds.
func NewRegistry(feedDir string) *Registry {
	r := &Registry{
		ind:     make(map[string]*Indicator),
		blocks:  make(map[string]*BlockedIP),
		feedDir: feedDir,
	}
	r.loadBuiltins()
	if feedDir != "" {
		_ = r.LoadFeeds()
	}
	return r
}

// loadBuiltins seeds the registry with the curated known-bad list referenced
// throughout the static analysers (JA3, scanners, signatures).
func (r *Registry) loadBuiltins() {
	builtins := []Indicator{
		// JA3 fingerprints for common offensive tools.
		{ID: "ja3-metasploit", Family: "Metasploit", Category: "ja3",
			Value: "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4", Severity: "critical",
			Description: "Metasploit Meterpreter default client fingerprint"},
		{ID: "ja3-trickbot", Family: "Trickbot", Category: "ja3",
			Value: "769,4-5-10-9-100-98-3-6-19-18-99-11-14-15", Severity: "critical",
			Description: "Trickbot loader TLS fingerprint"},
		{ID: "ja3-cobaltstrike", Family: "Cobalt Strike", Category: "ja3",
			Value: "771,49195-49199-49196-49200-52393-52392", Severity: "critical",
			Description: "Cobalt Strike beacon default profile"},
		{ID: "ja3-asyncrat", Family: "AsyncRAT", Category: "ja3",
			Value: "771,4865-4867-4866-49195-49199-52393", Severity: "critical",
			Description: "AsyncRAT C2 handshake"},
		{ID: "ja3-emotet", Family: "Emotet", Category: "ja3",
			Value: "771,49200-49196-49192-49188", Severity: "critical",
			Description: "Emotet banker fingerprint"},

		// Scanner user-agents.
		{ID: "scanner-nikto", Family: "Nikto", Category: "scanner", Value: "Nikto", Severity: "high"},
		{ID: "scanner-sqlmap", Family: "SQLMap", Category: "scanner", Value: "sqlmap", Severity: "critical"},
		{ID: "scanner-nmap", Family: "Nmap NSE", Category: "scanner", Value: "Nmap Scripting Engine", Severity: "high"},
		{ID: "scanner-masscan", Family: "Masscan", Category: "scanner", Value: "masscan", Severity: "high"},
		{ID: "scanner-zgrab", Family: "ZGrab", Category: "scanner", Value: "zgrab", Severity: "medium"},
		{ID: "scanner-dirsearch", Family: "Dirsearch", Category: "scanner", Value: "dirsearch", Severity: "medium"},
		{ID: "scanner-gobuster", Family: "Gobuster", Category: "scanner", Value: "gobuster", Severity: "medium"},
		{ID: "scanner-burp", Family: "Burp Suite", Category: "scanner", Value: "Burp", Severity: "high"},

		// Web attack signatures.
		{ID: "sig-sqli-union", Category: "signature", Family: "SQLi", Value: "union select", Severity: "critical"},
		{ID: "sig-sqli-or11", Category: "signature", Family: "SQLi", Value: "' or 1=1", Severity: "critical"},
		{ID: "sig-path-traversal", Category: "signature", Family: "Path Traversal", Value: "../../", Severity: "high"},
		{ID: "sig-cmd-injection", Category: "signature", Family: "Command Injection", Value: ";id;", Severity: "high"},
		{ID: "sig-xss-script", Category: "signature", Family: "XSS", Value: "<script>", Severity: "high"},

		// DNS heuristics.
		{ID: "dns-long-label", Category: "dns", Family: "DNS tunneling", Value: "label>40", Severity: "medium",
			Description: "DNS label length exceeds 40 bytes"},
		{ID: "dns-high-entropy", Category: "dns", Family: "DNS tunneling", Value: "entropy>4.2", Severity: "medium",
			Description: "Shannon entropy over 4.2 in DNS name"},
		{ID: "dns-txt-abuse", Category: "dns", Family: "DNS tunneling", Value: "txt-heavy", Severity: "medium",
			Description: "Excessive TXT queries"},
	}
	for i := range builtins {
		b := builtins[i]
		r.ind[b.ID] = &b
	}
}

// LoadFeeds reads *.txt files from feedDir. Each non-comment line is
// `id|family|category|severity|value|description?`.
func (r *Registry) LoadFeeds() error {
	entries, err := os.ReadDir(r.feedDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".txt" {
			continue
		}
		r.loadFeedFile(filepath.Join(r.feedDir, e.Name()))
	}
	return nil
}

func (r *Registry) loadFeedFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			continue
		}
		ind := &Indicator{
			ID: parts[0], Family: parts[1], Category: parts[2],
			Severity: parts[3], Value: parts[4],
		}
		if len(parts) >= 6 {
			ind.Description = parts[5]
		}
		r.mu.Lock()
		r.ind[ind.ID] = ind
		r.mu.Unlock()
	}
}

// MatchJA3 returns the matching indicator (if any) for a JA3 string.
func (r *Registry) MatchJA3(ja3 string) *Indicator {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ind := range r.ind {
		if ind.Category == "ja3" && strings.EqualFold(ind.Value, ja3) {
			atomic.AddUint64(&ind.Hits, 1)
			ind.LastHit = time.Now()
			return ind
		}
	}
	return nil
}

// MatchUA scans a user-agent header against scanner signatures.
func (r *Registry) MatchUA(ua string) *Indicator {
	r.mu.Lock()
	defer r.mu.Unlock()
	low := strings.ToLower(ua)
	for _, ind := range r.ind {
		if ind.Category == "scanner" && strings.Contains(low, strings.ToLower(ind.Value)) {
			atomic.AddUint64(&ind.Hits, 1)
			ind.LastHit = time.Now()
			return ind
		}
	}
	return nil
}

// MatchSignature scans payload text for known web-attack patterns.
func (r *Registry) MatchSignature(body string) *Indicator {
	r.mu.Lock()
	defer r.mu.Unlock()
	low := strings.ToLower(body)
	for _, ind := range r.ind {
		if ind.Category == "signature" && strings.Contains(low, strings.ToLower(ind.Value)) {
			atomic.AddUint64(&ind.Hits, 1)
			ind.LastHit = time.Now()
			return ind
		}
	}
	return nil
}

// Indicators returns a snapshot of all IOCs (ordered by category then family).
func (r *Registry) Indicators() []Indicator {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Indicator, 0, len(r.ind))
	for _, i := range r.ind {
		out = append(out, *i)
	}
	// Stable-ish sort: category, family, ID
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && less(out[j], out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func less(a, b Indicator) bool {
	if a.Category != b.Category {
		return a.Category < b.Category
	}
	if a.Family != b.Family {
		return a.Family < b.Family
	}
	return a.ID < b.ID
}

// Counts returns total IOCs and per-category counts.
func (r *Registry) Counts() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string]int{"total": len(r.ind)}
	for _, i := range r.ind {
		out[i.Category]++
	}
	return out
}

// ═══════════════════════════════════════════════════════════════════════════
// Block list
// ═══════════════════════════════════════════════════════════════════════════

// AddBlock inserts or refreshes a blocked IP entry.
func (r *Registry) AddBlock(ip, reason string, ttl time.Duration, auto bool) *BlockedIP {
	if net.ParseIP(ip) == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b := &BlockedIP{
		IP:        ip,
		Reason:    reason,
		AddedAt:   time.Now(),
		AutoAdded: auto,
	}
	if ttl > 0 {
		b.ExpiresAt = time.Now().Add(ttl)
	}
	r.blocks[ip] = b
	return b
}

// RemoveBlock deletes a block entry. Returns true if it existed.
func (r *Registry) RemoveBlock(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.blocks[ip]; ok {
		delete(r.blocks, ip)
		return true
	}
	return false
}

// IsBlocked returns true if ip is currently in the block list (and not expired).
func (r *Registry) IsBlocked(ip string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.blocks[ip]
	if !ok {
		return false
	}
	if !b.ExpiresAt.IsZero() && time.Now().After(b.ExpiresAt) {
		return false
	}
	return true
}

// Blocks returns a snapshot of active (non-expired) block entries.
func (r *Registry) Blocks() []BlockedIP {
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := time.Now()
	out := make([]BlockedIP, 0, len(r.blocks))
	for _, b := range r.blocks {
		if !b.ExpiresAt.IsZero() && now.After(b.ExpiresAt) {
			continue
		}
		out = append(out, *b)
	}
	return out
}
