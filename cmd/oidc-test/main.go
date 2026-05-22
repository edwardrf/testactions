package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	githubFederationAudience = "api://AzureADTokenExchange"
	managementScope          = "https://management.azure.com/.default"
)

// Mirrors defang's src/pkg/github/id_token.go GetIdToken — fetch the GH
// Actions OIDC JWT scoped to the given audience using the runner-injected
// ACTIONS_ID_TOKEN_REQUEST_URL/_TOKEN.
func getIDToken(ctx context.Context, audience string) (string, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL == "" || requestToken == "" {
		return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL or ACTIONS_ID_TOKEN_REQUEST_TOKEN not set — workflow missing `permissions: id-token: write`?")
	}
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("parse request URL: %w", err)
	}
	q := parsedURL.Query()
	q.Set("audience", audience)
	parsedURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("id token request returned HTTP %d: %s", resp.StatusCode, body)
	}
	var tr struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("decode id token response: %w", err)
	}
	return tr.Value, nil
}

func decodeJWTPayload(jwt string) (map[string]any, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 JWT segments, got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("base64-decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}
	return claims, nil
}

func main() {
	ctx := context.Background()

	clientID := os.Getenv("AZURE_CLIENT_ID")
	tenantID := os.Getenv("AZURE_TENANT_ID")
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	fmt.Printf("AZURE_CLIENT_ID=%q\nAZURE_TENANT_ID=%q\nAZURE_SUBSCRIPTION_ID=%q\n\n", clientID, tenantID, subID)
	if clientID == "" || tenantID == "" || subID == "" {
		fmt.Println("ERROR: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID are all required.")
		os.Exit(1)
	}

	fmt.Println("=== Step 1: fetch GitHub OIDC assertion ===")
	assertion, err := getIDToken(ctx, githubFederationAudience)
	if err != nil {
		fmt.Printf("ERROR fetching assertion: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Assertion (JWT, %d bytes):\n%s\n\n", len(assertion), assertion)

	if claims, err := decodeJWTPayload(assertion); err != nil {
		fmt.Printf("WARN: could not decode JWT payload: %v\n", err)
	} else {
		pretty, _ := json.MarshalIndent(claims, "", "  ")
		fmt.Printf("Decoded JWT claims:\n%s\n\n", pretty)
	}

	fmt.Println("=== Step 2: exchange assertion for an Azure ARM token ===")
	cred, err := azidentity.NewClientAssertionCredential(tenantID, clientID, func(ctx context.Context) (string, error) {
		return getIDToken(ctx, githubFederationAudience)
	}, nil)
	if err != nil {
		fmt.Printf("ERROR building ClientAssertionCredential: %v\n", err)
		os.Exit(1)
	}
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{managementScope}})
	if err != nil {
		fmt.Printf("ERROR exchanging assertion for ARM token: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ARM token acquired, ExpiresOn=%s, token prefix=%s...\n\n", tok.ExpiresOn.Format("2006-01-02T15:04:05Z"), tok.Token[:min(32, len(tok.Token))])

	fmt.Println("=== Step 3: ARM GET subscription ===")
	armURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s?api-version=2020-01-01", url.PathEscape(subID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, armURL, nil)
	if err != nil {
		fmt.Printf("ERROR building ARM request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("ERROR calling ARM: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Status: %s\nBody:\n%s\n", resp.Status, body)
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
