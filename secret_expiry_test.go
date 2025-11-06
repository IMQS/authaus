package authaus

import (
	"testing"
	"time"

	"github.com/IMQS/log"
	"github.com/stretchr/testify/assert"
)

// TestClientSecretExpiryNotification tests the client secret expiry notification mechanism
func TestClientSecretExpiryNotification(t *testing.T) {
	// Test data for tracking notifications
	var notificationCalls []secretExpiryNotification
	notificationCallback := func(providerName string, daysUntilExpiry int, expiryDate time.Time) {
		notificationCalls = append(notificationCalls, secretExpiryNotification{
			ProviderName:     providerName,
			DaysUntilExpiry:  daysUntilExpiry,
			ExpiryDate:       expiryDate,
		})
	}

	t.Run("OAuth provider secret expiry notification", func(t *testing.T) {
		notificationCalls = nil // Reset
		
		now := time.Now()
		expiryDate := now.Add(7 * 24 * time.Hour) // 7 days from now
		
		// Create OAuth config with provider that expires soon
		oauth := &OAuth{
			Config: ConfigOAuth{
				Providers: map[string]*ConfigOAuthProvider{
					"testProvider": {
						Type:                   OAuthProviderMSAAD,
						Title:                  "Test Provider",
						ClientID:               "test-client-id",
						ClientSecret:           "test-secret",
						ClientSecretExpiryDate: &expiryDate,
					},
				},
				SecretExpiryNotificationDays:     14, // Notify 14 days before expiry
				SecretExpiryNotificationCallback: notificationCallback,
				Verbose:                          true,
			},
		}
		
		// Mock parent with logger
		central := &Central{
			Log: log.New("stdout", true),
		}
		oauth.parent = central
		
		// Call the secret expiry check
		oauth.checkSecretExpiry()
		
		// Verify notification was triggered
		assert.Len(t, notificationCalls, 1, "Expected exactly one notification")
		if len(notificationCalls) > 0 {
			notification := notificationCalls[0]
			assert.Equal(t, "testProvider", notification.ProviderName)
			assert.Equal(t, 7, notification.DaysUntilExpiry)
			assert.True(t, notification.ExpiryDate.Equal(expiryDate))
		}
	})

	t.Run("MSAAD secret expiry notification", func(t *testing.T) {
		notificationCalls = nil // Reset
		
		now := time.Now()
		expiryDate := now.Add(10 * 24 * time.Hour) // 10 days from now
		
		// Create MSAAD config with secret that expires soon
		msaad := &MSAAD{
			config: ConfigMSAAD{
				ClientID:                         "test-msaad-client",
				ClientSecret:                     "test-msaad-secret",
				ClientSecretExpiryDate:           &expiryDate,
				SecretExpiryNotificationDays:     14, // Notify 14 days before expiry
				SecretExpiryNotificationCallback: notificationCallback,
				Verbose:                          true,
			},
			log: log.New("stdout", true),
		}
		
		// Call the secret expiry check
		msaad.checkSecretExpiry()
		
		// Verify notification was triggered
		assert.Len(t, notificationCalls, 1, "Expected exactly one notification")
		if len(notificationCalls) > 0 {
			notification := notificationCalls[0]
			assert.Equal(t, "MSAAD", notification.ProviderName)
			assert.Equal(t, 10, notification.DaysUntilExpiry)
			assert.True(t, notification.ExpiryDate.Equal(expiryDate))
		}
	})

	t.Run("No notification when secret not expiring soon", func(t *testing.T) {
		notificationCalls = nil // Reset
		
		now := time.Now()
		expiryDate := now.Add(30 * 24 * time.Hour) // 30 days from now
		
		oauth := &OAuth{
			Config: ConfigOAuth{
				Providers: map[string]*ConfigOAuthProvider{
					"testProvider": {
						Type:                   OAuthProviderMSAAD,
						Title:                  "Test Provider",
						ClientID:               "test-client-id",
						ClientSecret:           "test-secret",
						ClientSecretExpiryDate: &expiryDate,
					},
				},
				SecretExpiryNotificationDays:     14, // Notify 14 days before expiry
				SecretExpiryNotificationCallback: notificationCallback,
			},
		}
		
		central := &Central{
			Log: log.New("stdout", true),
		}
		oauth.parent = central
		
		oauth.checkSecretExpiry()
		
		// Verify no notification was triggered
		assert.Len(t, notificationCalls, 0, "Expected no notifications for secrets expiring in 30 days")
	})

	t.Run("No notification when secret already expired", func(t *testing.T) {
		notificationCalls = nil // Reset
		
		now := time.Now()
		expiryDate := now.Add(-5 * 24 * time.Hour) // 5 days ago
		
		oauth := &OAuth{
			Config: ConfigOAuth{
				Providers: map[string]*ConfigOAuthProvider{
					"testProvider": {
						Type:                   OAuthProviderMSAAD,
						Title:                  "Test Provider",
						ClientID:               "test-client-id",
						ClientSecret:           "test-secret",
						ClientSecretExpiryDate: &expiryDate,
					},
				},
				SecretExpiryNotificationDays:     14,
				SecretExpiryNotificationCallback: notificationCallback,
			},
		}
		
		central := &Central{
			Log: log.New("stdout", true),
		}
		oauth.parent = central
		
		oauth.checkSecretExpiry()
		
		// Verify no notification was triggered for expired secret
		assert.Len(t, notificationCalls, 0, "Expected no notifications for expired secrets")
	})

	t.Run("No notification when no callback configured", func(t *testing.T) {
		notificationCalls = nil // Reset
		
		now := time.Now()
		expiryDate := now.Add(7 * 24 * time.Hour) // 7 days from now
		
		oauth := &OAuth{
			Config: ConfigOAuth{
				Providers: map[string]*ConfigOAuthProvider{
					"testProvider": {
						Type:                   OAuthProviderMSAAD,
						Title:                  "Test Provider",
						ClientID:               "test-client-id",
						ClientSecret:           "test-secret",
						ClientSecretExpiryDate: &expiryDate,
					},
				},
				SecretExpiryNotificationDays: 14,
				// No callback configured
			},
		}
		
		central := &Central{
			Log: log.New("stdout", true),
		}
		oauth.parent = central
		
		oauth.checkSecretExpiry()
		
		// Verify no notification was triggered when no callback configured
		assert.Len(t, notificationCalls, 0, "Expected no notifications when callback not configured")
	})

	t.Run("Default notification threshold is 14 days", func(t *testing.T) {
		notificationCalls = nil // Reset
		
		now := time.Now()
		expiryDate := now.Add(13 * 24 * time.Hour) // 13 days from now
		
		oauth := &OAuth{
			Config: ConfigOAuth{
				Providers: map[string]*ConfigOAuthProvider{
					"testProvider": {
						Type:                   OAuthProviderMSAAD,
						Title:                  "Test Provider",
						ClientID:               "test-client-id",
						ClientSecret:           "test-secret",
						ClientSecretExpiryDate: &expiryDate,
					},
				},
				// SecretExpiryNotificationDays not set, should default to 14
				SecretExpiryNotificationCallback: notificationCallback,
			},
		}
		
		central := &Central{
			Log: log.New("stdout", true),
		}
		oauth.parent = central
		
		oauth.checkSecretExpiry()
		
		// Verify notification was triggered with default 14-day threshold
		assert.Len(t, notificationCalls, 1, "Expected notification with default 14-day threshold")
	})
}

// TestMultipleProvidersExpiryCheck tests checking multiple OAuth providers at once
func TestMultipleProvidersExpiryCheck(t *testing.T) {
	var notificationCalls []secretExpiryNotification
	notificationCallback := func(providerName string, daysUntilExpiry int, expiryDate time.Time) {
		notificationCalls = append(notificationCalls, secretExpiryNotification{
			ProviderName:     providerName,
			DaysUntilExpiry:  daysUntilExpiry,
			ExpiryDate:       expiryDate,
		})
	}

	now := time.Now()
	expiryDateSoon := now.Add(5 * 24 * time.Hour)  // 5 days from now
	expiryDateLater := now.Add(30 * 24 * time.Hour) // 30 days from now
	
	oauth := &OAuth{
		Config: ConfigOAuth{
			Providers: map[string]*ConfigOAuthProvider{
				"providerExpiringSoon": {
					Type:                   OAuthProviderMSAAD,
					Title:                  "Provider Expiring Soon",
					ClientID:               "test-client-id-1",
					ClientSecret:           "test-secret-1",
					ClientSecretExpiryDate: &expiryDateSoon,
				},
				"providerExpiringLater": {
					Type:                   OAuthProviderMSAAD,
					Title:                  "Provider Expiring Later",
					ClientID:               "test-client-id-2",
					ClientSecret:           "test-secret-2",
					ClientSecretExpiryDate: &expiryDateLater,
				},
				"providerNoExpiry": {
					Type:         OAuthProviderMSAAD,
					Title:        "Provider No Expiry",
					ClientID:     "test-client-id-3",
					ClientSecret: "test-secret-3",
					// No expiry date set
				},
			},
			SecretExpiryNotificationDays:     14,
			SecretExpiryNotificationCallback: notificationCallback,
		},
	}
	
	central := &Central{
		Log: log.New("stdout", true),
	}
	oauth.parent = central
	
	oauth.checkSecretExpiry()
	
	// Verify only the provider expiring soon triggered a notification
	assert.Len(t, notificationCalls, 1, "Expected exactly one notification")
	if len(notificationCalls) > 0 {
		assert.Equal(t, "providerExpiringSoon", notificationCalls[0].ProviderName)
		assert.Equal(t, 5, notificationCalls[0].DaysUntilExpiry)
	}
}

// secretExpiryNotification represents a captured notification call for testing
type secretExpiryNotification struct {
	ProviderName    string
	DaysUntilExpiry int
	ExpiryDate      time.Time
}