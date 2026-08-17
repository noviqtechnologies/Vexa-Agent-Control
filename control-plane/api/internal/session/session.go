package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var SessionDuration = 8 * time.Hour

var Secret []byte

func init() {
	if durStr := os.Getenv("SESSION_DURATION_HOURS"); durStr != "" {
		if hours, err := strconv.Atoi(durStr); err == nil && hours > 0 {
			SessionDuration = time.Duration(hours) * time.Hour
		}
	}

	if envSecret := os.Getenv("AGENTCONTROL_SESSION_SECRET"); envSecret != "" {
		Secret = []byte(envSecret)
	} else {
		Secret = make([]byte, 32)
		rand.Read(Secret)
	}
}

type SessionInfo struct {
	TenantID       string
	UserID         string
	IsAdmin        bool
	IsSaaSOperator bool
	Expiry         int64
}

// Validate parses and validates an HMAC-signed session cookie.
func Validate(cookieValue string) (*SessionInfo, error) {
	parts := strings.Split(cookieValue, "|")
	if len(parts) == 6 {
		// New format: tenantID|userID|isAdmin|isSaaSOperator|expiry|signature
		payload := fmt.Sprintf("%s|%s|%s|%s|%s", parts[0], parts[1], parts[2], parts[3], parts[4])
		signature := parts[5]

		mac := hmac.New(sha256.New, Secret)
		mac.Write([]byte(payload))
		expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

		if signature != expectedSignature {
			return nil, fmt.Errorf("invalid signature")
		}

		var expiry int64
		fmt.Sscanf(parts[4], "%d", &expiry)
		if time.Now().Unix() > expiry {
			return nil, fmt.Errorf("session expired")
		}

		return &SessionInfo{
			TenantID:       parts[0],
			UserID:         parts[1],
			IsAdmin:        parts[2] == "true",
			IsSaaSOperator: parts[3] == "true",
			Expiry:         expiry,
		}, nil
	} else if len(parts) == 4 {
		// Legacy 4-part format: userID|isAdmin|expiry|signature
		payload := fmt.Sprintf("%s|%s|%s", parts[0], parts[1], parts[2])
		signature := parts[3]

		mac := hmac.New(sha256.New, Secret)
		mac.Write([]byte(payload))
		expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

		if signature != expectedSignature {
			return nil, fmt.Errorf("invalid signature")
		}

		var expiry int64
		fmt.Sscanf(parts[2], "%d", &expiry)
		if time.Now().Unix() > expiry {
			return nil, fmt.Errorf("session expired")
		}

		return &SessionInfo{
			TenantID:       "00000000-0000-0000-0000-000000000001",
			UserID:         parts[0],
			IsAdmin:        parts[1] == "true",
			IsSaaSOperator: false,
			Expiry:         expiry,
		}, nil
	}

	return nil, fmt.Errorf("invalid cookie format")
}

// Create generates a 6-part HMAC-signed session cookie.
func Create(tenantID, userID string, isAdmin, isSaaSOperator bool) string {
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	expiry := time.Now().Add(SessionDuration).Unix()
	payload := fmt.Sprintf("%s|%s|%t|%t|%d", tenantID, userID, isAdmin, isSaaSOperator, expiry)

	mac := hmac.New(sha256.New, Secret)
	mac.Write([]byte(payload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s|%s", payload, signature)
}
