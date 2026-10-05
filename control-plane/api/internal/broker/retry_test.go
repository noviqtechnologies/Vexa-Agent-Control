package broker

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestClassifyUpstreamError_503ServerErrors(t *testing.T) {
	classes := []string{"502", "503", "504", "429", "connect_timeout"}

	// 503 should be retryable
	res := ClassifyUpstreamError(nil, http.StatusServiceUnavailable, nil, 10*time.Second, classes)
	if !res.IsRetryable {
		t.Errorf("expected 503 to be retryable, got non-retryable")
	}
	if res.ErrorClass != ErrorClassServer5xx {
		t.Errorf("expected ErrorClassServer5xx, got %s", res.ErrorClass)
	}

	// 502 should be retryable
	res502 := ClassifyUpstreamError(nil, http.StatusBadGateway, nil, 10*time.Second, classes)
	if !res502.IsRetryable {
		t.Errorf("expected 502 to be retryable, got non-retryable")
	}
}

func TestClassifyUpstreamError_429WithRetryAfter(t *testing.T) {
	classes := []string{"429", "503"}
	headers := make(http.Header)
	headers.Set("Retry-After", "2")

	// 2s retry-after fits in 10s deadline
	res := ClassifyUpstreamError(nil, http.StatusTooManyRequests, headers, 10*time.Second, classes)
	if !res.IsRetryable {
		t.Errorf("expected 429 with 2s Retry-After to be retryable in 10s deadline")
	}
	if res.RetryAfter != 2*time.Second {
		t.Errorf("expected RetryAfter = 2s, got %v", res.RetryAfter)
	}

	// 2s retry-after does NOT fit in 1s deadline
	resShort := ClassifyUpstreamError(nil, http.StatusTooManyRequests, headers, 1*time.Second, classes)
	if resShort.IsRetryable {
		t.Errorf("expected 429 to NOT be retryable when Retry-After exceeds remaining deadline")
	}
}

func TestClassifyUpstreamError_AuthAndClientErrorsNonRetryable(t *testing.T) {
	classes := []string{"503", "429"}

	// 401 Unauthorized should NEVER be retryable
	res401 := ClassifyUpstreamError(nil, http.StatusUnauthorized, nil, 10*time.Second, classes)
	if res401.IsRetryable {
		t.Errorf("expected 401 to be non-retryable")
	}
	if res401.ErrorClass != ErrorClassAuthFailed {
		t.Errorf("expected ErrorClassAuthFailed, got %s", res401.ErrorClass)
	}

	// 400 Bad Request should be non-retryable
	res400 := ClassifyUpstreamError(nil, http.StatusBadRequest, nil, 10*time.Second, classes)
	if res400.IsRetryable {
		t.Errorf("expected 400 to be non-retryable")
	}
}

func TestClassifyUpstreamError_NetworkTimeout(t *testing.T) {
	classes := []string{"connect_timeout", "503"}
	err := errors.New("upstream connection timed out: i/o timeout")

	res := ClassifyUpstreamError(err, 0, nil, 10*time.Second, classes)
	if !res.IsRetryable {
		t.Errorf("expected connect timeout error to be retryable")
	}
}

func TestComputeJitteredBackoff_Bounds(t *testing.T) {
	base := 50 * time.Millisecond
	max := 500 * time.Millisecond

	for attempt := 1; attempt <= 3; attempt++ {
		backoff := ComputeJitteredBackoff(attempt, base, max)
		if backoff < base {
			t.Errorf("backoff %v is less than base %v", backoff, base)
		}
		if backoff > max {
			t.Errorf("backoff %v is greater than max %v", backoff, max)
		}
	}
}
