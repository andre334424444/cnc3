// storage.go — JSON-backed persistence for users and attack history.
//
// Writes to a local JSON file. No external database required.
// Production note: swap this out for SQLite or Postgres if you
// need concurrent CNC instances sharing state.

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// --- data types ---

type UserRecord struct {
	Username    string `json:"username"`
	PasswordHash string `json:"password_hash"` // SHA256 hex
	IsAdmin     bool   `json:"is_admin"`
	MaxDuration int    `json:"max_duration"` // max attack seconds, 0 = unlimited
	Cooldown    int    `json:"cooldown"`     // seconds between attacks, 0 = none
	MaxBots     int    `json:"max_bots"`     // max bots per attack, 0 = unlimited
	CreatedAt   string `json:"created_at"`
}

type AttackRecord struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Type      string `json:"type"`
	Target    string `json:"target"`
	Duration  int    `json:"duration"`
	BotCount  int    `json:"bot_count"`
	Timestamp string `json:"timestamp"`
}

type StorageData struct {
	Users      []UserRecord   `json:"users"`
	Attacks    []AttackRecord `json:"attacks"`
	NextAtkID  int            `json:"next_attack_id"`
}

// --- storage engine ---

type Storage struct {
	mu   sync.RWMutex
	path string
	Data StorageData
}

func NewStorage(path string) *Storage {
	return &Storage{
		path: path,
		Data: StorageData{
			Users:     make([]UserRecord, 0),
			Attacks:   make([]AttackRecord, 0),
			NextAtkID: 1,
		},
	}
}

func (s *Storage) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		// First run — seed the default admin account.
		s.Data.Users = append(s.Data.Users, UserRecord{
			Username:     "admin",
			PasswordHash: hashPassword("nexus"), // default password
			IsAdmin:      true,
			MaxDuration:  0,
			Cooldown:     0,
			MaxBots:      0,
			CreatedAt:    time.Now().Format(time.RFC3339),
		})
		return fmt.Errorf("no data file")
	}

	return json.Unmarshal(data, &s.Data)
}

func (s *Storage) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s.Data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

// --- user operations ---

func (s *Storage) ValidateUser(username, password string) *UserRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hash := hashPassword(password)
	for i := range s.Data.Users {
		if s.Data.Users[i].Username == username && s.Data.Users[i].PasswordHash == hash {
			return &s.Data.Users[i]
		}
	}
	return nil
}

func (s *Storage) AddUser(username, password string, isAdmin bool, maxDur, cooldown, maxBots int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicates.
	for _, u := range s.Data.Users {
		if u.Username == username {
			return fmt.Errorf("user '%s' already exists", username)
		}
	}

	s.Data.Users = append(s.Data.Users, UserRecord{
		Username:     username,
		PasswordHash: hashPassword(password),
		IsAdmin:      isAdmin,
		MaxDuration:  maxDur,
		Cooldown:     cooldown,
		MaxBots:      maxBots,
		CreatedAt:    time.Now().Format(time.RFC3339),
	})
	return s.unsafeSave()
}

func (s *Storage) RemoveUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, u := range s.Data.Users {
		if u.Username == username {
			s.Data.Users = append(s.Data.Users[:i], s.Data.Users[i+1:]...)
			return s.unsafeSave()
		}
	}
	return fmt.Errorf("user '%s' not found", username)
}

func (s *Storage) ListUsers() []UserRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]UserRecord, len(s.Data.Users))
	copy(users, s.Data.Users)
	return users
}

// --- attack history ---

func (s *Storage) RecordAttack(username, atkType, target string, duration, botCount int) AttackRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec := AttackRecord{
		ID:        s.Data.NextAtkID,
		Username:  username,
		Type:      atkType,
		Target:    target,
		Duration:  duration,
		BotCount:  botCount,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	s.Data.NextAtkID++
	s.Data.Attacks = append(s.Data.Attacks, rec)

	// Keep only the last 500 attacks in memory.
	if len(s.Data.Attacks) > 500 {
		s.Data.Attacks = s.Data.Attacks[len(s.Data.Attacks)-500:]
	}

	s.unsafeSave()
	return rec
}

func (s *Storage) GetHistory(limit int) []AttackRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	attacks := s.Data.Attacks
	if limit > 0 && limit < len(attacks) {
		attacks = attacks[len(attacks)-limit:]
	}
	result := make([]AttackRecord, len(attacks))
	copy(result, attacks)
	return result
}

// --- internal ---

func (s *Storage) unsafeSave() error {
	// Caller MUST hold s.mu (write lock).
	data, err := json.MarshalIndent(s.Data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

func hashPassword(pw string) string {
	h := sha256.Sum256([]byte(pw))
	return fmt.Sprintf("%x", h)
}
