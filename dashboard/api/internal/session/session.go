package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

var Secret []byte

func init() {
	Secret = make([]byte, 32)
	rand.Read(Secret)
}

func Validate(cookieValue string) (string, bool, error) {
	parts := strings.Split(cookieValue, "|")
	if len(parts) != 4 {
		return "", false, fmt.Errorf("invalid cookie format")
	}
	
	payload := fmt.Sprintf("%s|%s|%s", parts[0], parts[1], parts[2])
	signature := parts[3]
	
	mac := hmac.New(sha256.New, Secret)
	mac.Write([]byte(payload))
	expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	
	if signature != expectedSignature {
		return "", false, fmt.Errorf("invalid signature")
	}
	
	var expiry int64
	fmt.Sscanf(parts[2], "%d", &expiry)
	if time.Now().Unix() > expiry {
		return "", false, fmt.Errorf("session expired")
	}
	
	isAdmin := parts[1] == "true"
	return parts[0], isAdmin, nil
}

func Create(userID string, isAdmin bool) string {
	expiry := time.Now().Add(24 * time.Hour).Unix()
	payload := fmt.Sprintf("%s|%t|%d", userID, isAdmin, expiry)
	
	mac := hmac.New(sha256.New, Secret)
	mac.Write([]byte(payload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	
	return fmt.Sprintf("%s|%s", payload, signature)
}
