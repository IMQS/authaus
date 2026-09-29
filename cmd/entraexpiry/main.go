package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type probeConfig struct {
	TenantID          string
	ClientID          string
	ClientSecret      string
	ClientSecretKeyID string
	Timeout           time.Duration
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type application struct {
	ID                  string               `json:"id"`
	DisplayName         string               `json:"displayName"`
	PasswordCredentials []passwordCredential `json:"passwordCredentials"`
}

type applicationsResponse struct {
	Value []application `json:"value"`
}

type passwordCredential struct {
	KeyID       string `json:"keyId"`
	DisplayName string `json:"displayName"`
	EndDateTime string `json:"endDateTime"`
}

func main() {
	var config probeConfig
	flag.StringVar(&config.TenantID, "tenant-id", "", "Microsoft Entra tenant ID (required)")
	flag.StringVar(&config.ClientID, "client-id", "", "application/client ID (required)")
	flag.StringVar(&config.ClientSecret, "client-secret", "", "client secret; prefer ENTRA_CLIENT_SECRET")
	flag.StringVar(&config.ClientSecretKeyID, "key-id", "", "password credential key ID (required when multiple secrets exist)")
	flag.DurationVar(&config.Timeout, "timeout", 15*time.Second, "HTTP timeout")
	flag.Parse()

	if config.ClientSecret == "" {
		config.ClientSecret = os.Getenv("ENTRA_CLIENT_SECRET")
	}
	if err := validateConfig(config); err != nil {
		fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()
	result, err := probe(ctx, http.DefaultClient, config)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("Entra application: %s\n", result.DisplayName)
	fmt.Printf("Application object ID: %s\n", result.ApplicationObjectID)
	fmt.Printf("Password credential key ID: %s\n", result.Credential.KeyID)
	if result.Credential.DisplayName != "" {
		fmt.Printf("Password credential name: %s\n", result.Credential.DisplayName)
	}
	fmt.Printf("Client secret expiry: %s\n", result.Expiry.Format(time.RFC3339))
}

type probeResult struct {
	DisplayName         string
	ApplicationObjectID string
	Credential          passwordCredential
	Expiry              time.Time
}

func validateConfig(config probeConfig) error {
	missing := make([]string, 0, 3)
	if config.TenantID == "" {
		missing = append(missing, "tenant-id")
	}
	if config.ClientID == "" {
		missing = append(missing, "client-id")
	}
	if config.ClientSecret == "" {
		missing = append(missing, "client-secret or ENTRA_CLIENT_SECRET")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required value(s): %s", strings.Join(missing, ", "))
	}
	if config.Timeout <= 0 {
		return errors.New("timeout must be greater than zero")
	}
	return nil
}

func probe(ctx context.Context, client *http.Client, config probeConfig) (probeResult, error) {
	token, err := acquireToken(ctx, client, config)
	if err != nil {
		return probeResult{}, err
	}

	application, err := getApplication(ctx, client, token, config)
	if err != nil {
		return probeResult{}, err
	}

	credentials := application.PasswordCredentials
	if config.ClientSecretKeyID != "" {
		credentials = make([]passwordCredential, 0, 1)
		for _, credential := range application.PasswordCredentials {
			if credential.KeyID == config.ClientSecretKeyID {
				credentials = append(credentials, credential)
			}
		}
	}
	if len(credentials) == 0 {
		return probeResult{}, fmt.Errorf("no matching password credential found for application %q", application.ID)
	}
	if len(credentials) > 1 {
		return probeResult{}, fmt.Errorf("application %q has multiple password credentials; provide -key-id", application.ID)
	}

	expiry, err := time.Parse(time.RFC3339, credentials[0].EndDateTime)
	if err != nil {
		return probeResult{}, fmt.Errorf("invalid credential endDateTime %q: %w", credentials[0].EndDateTime, err)
	}
	return probeResult{
		DisplayName:         application.DisplayName,
		ApplicationObjectID: application.ID,
		Credential:          credentials[0],
		Expiry:              expiry,
	}, nil
}

func acquireToken(ctx context.Context, client *http.Client, config probeConfig) (string, error) {
	endpoint := "https://login.microsoftonline.com/" + url.PathEscape(config.TenantID) + "/oauth2/v2.0/token"
	form := url.Values{
		"client_id":     {config.ClientID},
		"client_secret": {config.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("request Entra token: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Entra token request returned HTTP %s", response.Status)
	}

	var token tokenResponse
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		return "", fmt.Errorf("decode Entra token response: %w", err)
	}
	if token.TokenType != "Bearer" || token.AccessToken == "" {
		return "", errors.New("Entra token response did not contain a bearer access token")
	}
	return token.AccessToken, nil
}

func getApplication(ctx context.Context, client *http.Client, token string, config probeConfig) (application, error) {
	var endpoint string
	filter := "appId eq '" + strings.ReplaceAll(config.ClientID, "'", "''") + "'"
	endpoint = "https://graph.microsoft.com/v1.0/applications?$filter=" + url.QueryEscape(filter) + "&$select=id,displayName,passwordCredentials"

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return application{}, fmt.Errorf("create Graph request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := client.Do(request)
	if err != nil {
		return application{}, fmt.Errorf("request Graph application metadata: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return application{}, fmt.Errorf("Graph application request returned HTTP %s", response.Status)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return application{}, fmt.Errorf("read Graph application response: %w", err)
	}
	var results applicationsResponse
	if err := json.Unmarshal(body, &results); err != nil {
		return application{}, fmt.Errorf("decode Graph application search response: %w", err)
	}
	if len(results.Value) != 1 {
		return application{}, fmt.Errorf("Graph returned %d applications for ClientID", len(results.Value))
	}
	return results.Value[0], nil
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "entraexpiry:", err)
	os.Exit(1)
}
