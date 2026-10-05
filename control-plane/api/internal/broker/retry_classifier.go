package broker

import (
	"errors"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Standard error classifications
const (
	ErrorClassConnectTimeout  = "connect_timeout"
	ErrorClassReadTimeout     = "read_timeout"
	ErrorClassDNSError        = "dns_error"
	ErrorClassRateLimit429    = "rate_limit_429"
	ErrorClassServer5xx       = "server_5xx"
	ErrorClassClient4xx       = "client_4xx"
	ErrorClassAuthFailed      = "auth_failed"
	ErrorClassStreamCommitted = "stream_committed_failure"
	ErrorClassNonRetryable    = "non_retryable"
)

// ClassificationResult holds retry eligibility evaluation.
type ClassificationResult struct {
	IsRetryable       bool
	ErrorClass        string
	RetryAfter        time.Duration
	CanFitInDeadline  bool
	ReasonDescription string
}

// ClassifyUpstreamError determines if an upstream response/error is retryable under the deadline.
func ClassifyUpstreamError(
	err error,
	statusCode int,
	headers http.Header,
	remainingDeadline time.Duration,
	retryClasses []string,
) ClassificationResult {
	res := ClassificationResult{
		IsRetryable: false,
		ErrorClass:  ErrorClassNonRetryable,
	}

	// 1. Network / Transport Errors
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			res.ErrorClass = ErrorClassConnectTimeout
			res.IsRetryable = isClassAllowed(ErrorClassConnectTimeout, retryClasses)
			res.ReasonDescription = "Upstream connection timed out before receiving response headers"
		} else if strings.Contains(strings.ToLower(err.Error()), "dns") || strings.Contains(strings.ToLower(err.Error()), "no such host") {
			res.ErrorClass = ErrorClassDNSError
			res.IsRetryable = isClassAllowed(ErrorClassDNSError, retryClasses)
			res.ReasonDescription = "DNS resolution failure contacting provider endpoint"
		} else {
			res.ErrorClass = ErrorClassConnectTimeout
			res.IsRetryable = isClassAllowed("503", retryClasses)
			res.ReasonDescription = err.Error()
		}
	} else if statusCode > 0 {
		statusStr := strconv.Itoa(statusCode)

		// 2. HTTP Status Codes
		switch statusCode {
		case http.StatusTooManyRequests: // 429
			res.ErrorClass = ErrorClassRateLimit429
			res.IsRetryable = isClassAllowed("429", retryClasses)
			res.ReasonDescription = "Provider rate limit exceeded (HTTP 429)"

			if headers != nil {
				retryAfterHdr := headers.Get("Retry-After")
				if retryAfterHdr != "" {
					if sec, parseErr := strconv.Atoi(strings.TrimSpace(retryAfterHdr)); parseErr == nil && sec > 0 {
						res.RetryAfter = time.Duration(sec) * time.Second
					}
				}
			}

		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout: // 502, 503, 504
			res.ErrorClass = ErrorClassServer5xx
			res.IsRetryable = isClassAllowed(statusStr, retryClasses) || isClassAllowed("5xx", retryClasses)
			res.ReasonDescription = "Transient upstream server error"

		case http.StatusUnauthorized, http.StatusForbidden: // 401, 403
			res.ErrorClass = ErrorClassAuthFailed
			res.IsRetryable = false // Never retry credential auth failure with same credential
			res.ReasonDescription = "Provider authentication or permission error"

		default:
			if statusCode >= 400 && statusCode < 500 {
				res.ErrorClass = ErrorClassClient4xx
				res.IsRetryable = false
				res.ReasonDescription = "Client error rejected by upstream provider"
			} else if statusCode >= 500 {
				res.ErrorClass = ErrorClassServer5xx
				res.IsRetryable = isClassAllowed("5xx", retryClasses)
				res.ReasonDescription = "Upstream server failure"
			}
		}
	}

	// 3. Check remaining deadline boundary
	if res.IsRetryable {
		minRequired := res.RetryAfter + 500*time.Millisecond // Need at least backoff + 500ms for attempt
		if remainingDeadline > 0 && remainingDeadline < minRequired {
			res.IsRetryable = false
			res.CanFitInDeadline = false
			res.ReasonDescription = "Retryable error cannot fit within remaining request deadline"
		} else {
			res.CanFitInDeadline = true
		}
	}

	return res
}

func isClassAllowed(target string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	targetLower := strings.ToLower(target)
	for _, c := range allowed {
		if strings.ToLower(c) == targetLower || c == "*" {
			return true
		}
	}
	return false
}

// ComputeJitteredBackoff calculates exponential backoff with full jitter.
func ComputeJitteredBackoff(attempt int, baseBackoff, maxBackoff time.Duration) time.Duration {
	if baseBackoff <= 0 {
		baseBackoff = 50 * time.Millisecond
	}
	if maxBackoff <= 0 {
		maxBackoff = 2 * time.Second
	}

	mult := 1 << uint(attempt)
	temp := baseBackoff * time.Duration(mult)
	if temp > maxBackoff {
		temp = maxBackoff
	}

	// Full jitter: random duration between 0 and temp
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	jittered := time.Duration(r.Int63n(int64(temp)))
	if jittered < baseBackoff {
		jittered = baseBackoff
	}
	return jittered
}
