package authaus

import (
	"database/sql"
	"fmt"
	"github.com/IMQS/log"
	"sync"
	"time"
)

// CheckLogEntry represents a single session check log entry
type CheckLogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	SessionToken string    `json:"session_token"`
	UserId       UserId    `json:"user_id"`
}

// CheckUsageTracker manages in-memory storage and periodic flushing of session check logs
type CheckUsageTracker struct {
	config           ConfigUsageTracking
	log              *log.Logger
	logs             []CheckLogEntry
	mutex            sync.RWMutex
	stopChan         chan struct{}
	doneChan         chan struct{}
	flushDoneChan    chan struct{}
	stopOnce         sync.Once
	flushTicker      *time.Ticker
	flushing         bool // Track if a flush is in progress
	db               *sql.DB
	droppedLogsCount int64
	memDump          []string // For testing purposes
}

// NewCheckUsageTracker creates a new usage tracker instance
func NewCheckUsageTracker(c ConfigUsageTracking, log *log.Logger, db *sql.DB) *CheckUsageTracker {
	c.SetDefaults()
	tracker := &CheckUsageTracker{
		config:        c,
		log:           log,
		logs:          make([]CheckLogEntry, 0),
		stopChan:      make(chan struct{}),
		doneChan:      make(chan struct{}),
		flushDoneChan: make(chan struct{}, 1),
		db:            db, // Database connection will be set later
	}
	if tracker.config.Test_MemDump {
		tracker.memDump = make([]string, 0)
	}
	return tracker
}

func (t *CheckUsageTracker) Initialize(logger *log.Logger) {
	if logger != nil {
		t.log = logger

		if t.config.Enabled {
			t.start()
		}

		if t.db == nil {
			t.log.Warn("CheckUsageTracker initialized without a database connection, logs will not be persisted")
		} else {
			t.log.Info("CheckUsageTracker initialized with database connection")
		}
	}
}

// LogCheck adds a check request to the in-memory log
func (t *CheckUsageTracker) LogCheck(sessionToken string, token *Token) {
	if !t.config.Enabled {
		return
	}

	entry := CheckLogEntry{
		Timestamp:    time.Now().UTC(),
		SessionToken: sessionToken,
		UserId:       token.UserId,
	}

	t.mutex.Lock()
	if len(t.logs) >= t.config.MaxEntries {
		t.droppedLogsCount++
		// drop entry
	} else {
		t.logs = append(t.logs, entry)
	}
	t.mutex.Unlock()
}

// start begins the periodic flush process
func (t *CheckUsageTracker) start() {
	flushInterval := time.Duration(t.config.FlushIntervalSeconds) * time.Second
	if flushInterval <= 0 {
		flushInterval = 60 * time.Second // Default to 1 minute
	}

	t.flushTicker = time.NewTicker(flushInterval)

	go func() {
		defer close(t.doneChan)
		for {
			select {
			case <-t.flushTicker.C:
				t.flush()
			case <-t.stopChan:
				t.flushTicker.Stop()
				t.flush() // Final flush before stopping
				return
			}
		}
	}()
}

// Stop gracefully shuts down the usage tracker
func (t *CheckUsageTracker) Stop() {
	t.stopOnce.Do(func() {
		if t.flushTicker != nil && t.stopChan != nil {
			close(t.stopChan)
			<-t.doneChan      // Wait for main flush management goroutine to finish
			<-t.flushDoneChan // Wait for any ongoing flush operation to complete
		}
	})
}

// flush writes the in-memory logs to persistent storage and clears the memory
// TODO : Implement a more generic persistence abstraction (e.g. Provider pattern)
func (t *CheckUsageTracker) flush() {
	t.mutex.Lock()

	if len(t.logs) == 0 || t.flushing {
		t.mutex.Unlock()
		return
	}

	// Create a copy of logs to persist
	logsToPersist := make([]CheckLogEntry, len(t.logs))
	copy(logsToPersist, t.logs)
	logsCount := len(t.logs)

	// Mark that we're flushing to prevent concurrent flushes
	t.flushing = true
	t.mutex.Unlock()

	// Persist logs in a separate goroutine to avoid blocking
	go func() {
		err := t.persistLogs(logsToPersist)

		// Handle the result of persistence
		t.mutex.Lock()
		t.flushing = false

		if err != nil {
			t.log.Errorf("Failed to persist check usage logs: %v", err)
			// Keep the logs in memory for retry - don't clear them
		} else {
			// Only clear logs after successful persistence
			// Check if new logs were added during persistence
			if len(t.logs) >= logsCount {
				// Remove the persisted logs (first logsCount entries)
				t.logs = t.logs[logsCount:]
			} else {
				// Shouldn't happen, but clear all if somehow we have fewer logs
				t.logs = t.logs[:0]
			}
		}
		t.mutex.Unlock()
		t.flushDoneChan <- struct{}{}
	}()
}

// persistLogs writes logs to persistent storage using authaus persistence abstraction
func (t *CheckUsageTracker) persistLogs(logs []CheckLogEntry) error {
	if t.db != nil {
		// Example SQL insert statement, assuming a table structure exists
		stmt, err := t.db.Prepare("INSERT INTO session_check_logs (ts, session_token, user_id) VALUES ($1, $2, $3)")
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, entry := range logs {
			_, err = stmt.Exec(entry.Timestamp, entry.SessionToken, entry.UserId)
			if err != nil {
				return err
			}
		}
	} else {
		// this is for testing, NOT production
		if t.config.Test_MemDump {
			// If no database connection, just clear
			for _, entry := range logs {
				t.memDump = append(t.memDump, checkLogString(entry))
			}
		}
	}
	return nil
}

func checkLogString(entry CheckLogEntry) string {
	return "Persisting CheckUsage: time=" + entry.Timestamp.Format(time.RFC3339) +
		" token=" + entry.SessionToken +
		" userId=" + fmt.Sprint(entry.UserId)
}
