package authaus

import (
	"github.com/IMQS/log"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestConfigUsageTracking_SetDefaults(t *testing.T) {
	config := &ConfigUsageTracking{}
	config.SetDefaults()

	assert.Equal(t, 60, config.FlushIntervalSeconds, "FlushIntervalSeconds should be 60 after SetDefaults")
	assert.Equal(t, 10000, config.MaxEntries, "MaxEntries should be 10000 after SetDefaults")
}

func TestCheckUsageTracker_LogCheck_Disabled(t *testing.T) {
	// Test that when usage tracking is disabled, LogCheck does nothing
	config := ConfigUsageTracking{Enabled: false}
	tracker := NewCheckUsageTracker(config, testLogStdOut(), nil)

	token := &Token{
		Identity: "testuser",
		UserId:   1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	// This should not panic or cause issues when disabled
	tracker.LogCheck("session123", token)

	// Should have no logs
	tracker.mutex.RLock()
	logCount := len(tracker.logs)
	tracker.mutex.RUnlock()

	assert.Equal(t, 0, logCount, "Expected no logs when usage tracking is disabled")
}

func TestCheckUsageTracker_LogCheck_Enabled(t *testing.T) {
	// Test that when usage tracking is enabled, LogCheck stores entries
	config := ConfigUsageTracking{Enabled: true, FlushIntervalSeconds: 60}
	tracker := NewCheckUsageTracker(config, testLogStdOut(), nil)
	defer tracker.Stop()

	token := &Token{
		Identity: "testuser",
		UserId:   1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	sessionToken := "session123"
	tracker.LogCheck(sessionToken, token)

	// Verify log was created
	tracker.mutex.RLock()
	logCount := len(tracker.logs)
	if logCount != 1 {
		t.Errorf("Expected 1 log entry, got %d", logCount)
	} else {
		entry := tracker.logs[0]
		assert.Equal(t, entry.SessionToken, sessionToken, "Expected session token to match")
		assert.Equal(t, entry.UserId, token.UserId, "Expected userId to match")
		assert.True(t, !entry.Timestamp.IsZero(), "Expected timestamp to be set")
	}
	tracker.mutex.RUnlock()
}

func TestCheckUsageTracker_FlushBehavior(t *testing.T) {
	// Test that flush handles persistence failures correctly
	config := ConfigUsageTracking{Enabled: true, FlushIntervalSeconds: 1}
	tracker := NewCheckUsageTracker(config, testLogStdOut(), nil)
	defer tracker.Stop()

	// Add some logs
	token := &Token{
		Identity: "testuser",
		UserId:   1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	tracker.LogCheck("session1", token)
	tracker.LogCheck("session2", token)

	// Verify logs exist before flush
	tracker.mutex.RLock()
	initialCount := len(tracker.logs)
	tracker.mutex.RUnlock()

	assert.Equal(t, 2, initialCount, "Expected 2 logs before flush")

	// Call flush manually
	tracker.flush()

	// Wait a bit for the goroutine
	<-tracker.flushDoneChan

	// Since persistLogs currently always succeeds,
	// logs should be cleared after flush
	tracker.mutex.RLock()
	finalCount := len(tracker.logs)
	flushing := tracker.flushing
	tracker.mutex.RUnlock()

	assert.Equal(t, 0, finalCount, "Expected no logs after successful flush")
	assert.False(t, flushing, "Expected flushing to be false after flush completes")
}

func TestCheckUsageTracker_Overload(t *testing.T) {
	config := ConfigUsageTracking{
		Enabled:              true,
		FlushIntervalSeconds: 10,
		MaxEntries:           1000,
		Test_MemDump:         true,
	}
	l := testLogStdOut()
	tracker := NewCheckUsageTracker(config, l, nil)
	tracker.Initialize(l)
	defer tracker.Stop()

	token := &Token{
		Identity: "testuser",
		UserId:   1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	maxSessions := 3000
	sessions := makeSessions(maxSessions)
	// add all sessions immediately, which should exceed capacity
	for i := 0; i < maxSessions; i++ {
		tracker.LogCheck(sessions[i], token)
	}

	tracker.mutex.RLock()
	initialCount := len(tracker.logs)
	droppedCount := tracker.droppedLogsCount
	tracker.mutex.RUnlock()
	t.Logf("Initial log count: %d, Dropped count: %d", initialCount, droppedCount)
	assert.Equal(t, config.MaxEntries, initialCount, "Expect only 1000 entries to be 'persisted'")
	assert.Equal(t, int64(maxSessions-config.MaxEntries), droppedCount, "Expect 1000 entries to be dropped due to overload")
}

// TODO : Find a more comprehensive way to test performance
func TestCheckUsageTracker_Perf(t *testing.T) {
	config := ConfigUsageTracking{
		Enabled:              true,
		FlushIntervalSeconds: 1,
		MaxEntries:           300000,
		Test_MemDump:         true,
	}
	l := testLogStdOut()
	tracker := NewCheckUsageTracker(config, l, nil)
	tracker.Initialize(l)
	defer tracker.Stop()

	// Add some logs
	token := &Token{
		Identity: "testuser",
		UserId:   1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	maxSessions := 300000
	sessions := makeSessions(maxSessions)

	ms1 := time.Now().UnixMilli()
	for i := 0; i < maxSessions; i++ {
		tracker.LogCheck(sessions[i], token)
	}
	ms2 := time.Now().UnixMilli()
	// Verify logs exist before flush
	msTotal := ms2 - ms1
	assert.Less(t, ms2-ms1, (1 * time.Second).Milliseconds(), "Expected less than 1 second for logging %d sessions", maxSessions)
	p := message.NewPrinter(language.Afrikaans)
	t.Log(p.Printf("Total time for %d logs: %d %s", maxSessions, msTotal, "ms"))

	tracker.mutex.RLock()
	initialCount := len(tracker.logs)
	tracker.mutex.RUnlock()

	assert.Equal(t, maxSessions, initialCount, "Expected %d logs before flush", maxSessions)
	// Call flush manually
	tracker.flush()
	t.Log("Before 'Stop'")
	tracker.Stop()
	t.Log("After 'Stop'")

	// Since persistLogs currently always succeeds (just logs),
	// all logs should be cleared after flush
	tracker.mutex.RLock()
	finalCount := len(tracker.logs)
	persistCount := len(tracker.memDump)
	flushing := tracker.flushing
	droppedCount := tracker.droppedLogsCount
	tracker.mutex.RUnlock()
	t.Logf("Final log count: %d, Persist count: %d, Dropped count: %d, Flushing: %t", finalCount, persistCount, droppedCount, flushing)

	assert.Equal(t, 0, finalCount, "Expected no logs after flush")
	assert.Equal(t, maxSessions, persistCount, "Expected memDump to contain %d entries", maxSessions)
	assert.Equal(t, 0, droppedCount, "Expected no dropped logs")
	if flushing {
		t.Error("Expected flushing to be false after flush completes")
	}
	assert.NotEqual(t, flushing, true, "Expected flushing to be false after flush completes")
}

func TestCheckUsageTracker_NormalFlush(t *testing.T) {
	config := ConfigUsageTracking{
		Enabled:              true,
		FlushIntervalSeconds: 1,
		MaxEntries:           100000,
		Test_MemDump:         true,
	}

	token := &Token{
		Identity: "testuser",
		UserId:   1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	maxSessions := 10000
	sessions := makeSessions(maxSessions)

	l := testLogStdOut()
	tracker := NewCheckUsageTracker(config, l, nil)
	tracker.Initialize(l)
	defer tracker.Stop()

	for i := 0; i < maxSessions; i++ {
		tracker.LogCheck("session"+sessions[i], token)
	}

	// Verify logs exist before flush
	tracker.mutex.RLock()
	initialCount := len(tracker.logs)
	tracker.mutex.RUnlock()

	assert.Equal(t, maxSessions, initialCount, "Expected %d logs before flush", maxSessions)

	// wait at least flush interval
	time.Sleep(1*time.Second + 100*time.Millisecond)

	// Since persistLogs currently always succeeds (just logs),
	// all logs should be cleared after flush interval
	tracker.mutex.RLock()
	finalCount := len(tracker.logs)
	persistCount := len(tracker.memDump)
	flushing := tracker.flushing
	droppedCount := tracker.droppedLogsCount
	tracker.mutex.RUnlock()
	t.Logf("Final log count: %d, Persist count: %d, Dropped count: %d, Flushing: %t", finalCount, persistCount, droppedCount, flushing)

	assert.Equal(t, 0, finalCount, "Expected no logs after flush")
	assert.Equal(t, maxSessions, persistCount, "Expected memDump to contain %d entries", maxSessions)
	assert.Equal(t, int64(0), droppedCount, "Expected no dropped logs")
	assert.False(t, flushing, "Expected flushing to be false after flush completes")
}

func TestCheckUsageTracker_FinalFlush(t *testing.T) {
	config := ConfigUsageTracking{
		Enabled:              true,
		FlushIntervalSeconds: 1,
		MaxEntries:           100000,
		Test_MemDump:         true,
	}

	token := &Token{
		Identity: "testuser",
		UserId:   1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	maxSessions := 10000
	sessions := makeSessions(maxSessions)

	l := testLogStdOut()
	tracker := NewCheckUsageTracker(config, l, nil)
	tracker.Initialize(l)
	defer tracker.Stop()

	for i := 0; i < maxSessions; i++ {
		tracker.LogCheck("session"+sessions[i], token)
	}

	// Verify logs exist before flush
	tracker.mutex.RLock()
	initialCount := len(tracker.logs)
	tracker.mutex.RUnlock()
	assert.Equal(t, maxSessions, initialCount, "Expected %d logs before final flush", maxSessions)

	//stop tracker (expect to flush automatically)
	tracker.Stop()
	time.Sleep(100 * time.Millisecond)
	tracker.mutex.RLock()
	finalCount := len(tracker.logs)
	tracker.mutex.RUnlock()
	assert.Equal(t, 0, finalCount, "Expected no logs after final flush")
}

func makeSessions(maxSessions int) []string {
	sessions := make([]string, maxSessions)
	for k := 0; k < maxSessions; k++ {
		i := k % 10 // Use 10 different session tokens to simulate real usage
		sessions[k] = "session" + string(strconv.Itoa(i))
	}
	return sessions
}

func testLogStdOut() *log.Logger {
	log1 := log.New(resolveLogfile(log.Stdout), runtime.GOOS != "windows")
	return log1
}
