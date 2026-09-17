package device

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

var (
	ErrDeviceLimitReached = errors.New("device enrollment limit reached for current license tier")
	ErrLicenseExpired     = errors.New("license expired")
)

// CheckDeviceEnrollmentLimit verifies if the organization can enroll another device.
// During Early Access: up to 5 devices, no time limit.
// Once a license key is activated, the key's tier and max_devices apply.
// Enterprise tier = unlimited (-1).
func CheckDeviceEnrollmentLimit(ctx context.Context, st *store.Store, organizationID string) error {
	if st == nil {
		return nil
	}
	org, err := st.GetOrganization(ctx, organizationID)
	if err != nil {
		return fmt.Errorf("lookup organization license: %w", err)
	}

	// 1. Hard expiry check — only applies when a license key is present and has an explicit expiry.
	//    Early Access (no license key) has no time limit; only the 5-device cap applies.
	if org.LicenseKeyJWT != "" && org.LicenseExpiresAt != nil && time.Now().After(*org.LicenseExpiresAt) {
		return fmt.Errorf("%w: license expired on %s. Please activate or renew your license key",
			ErrLicenseExpired, org.LicenseExpiresAt.Format("2006-01-02"))
	}

	// 2. Capacity quota check
	maxDevices := org.MaxDevices
	if maxDevices <= 0 && org.LicenseTier == "enterprise" {
		return nil // Unlimited
	}
	if maxDevices <= 0 {
		switch org.LicenseTier {
		case "team":
			maxDevices = 5 // Early Access quota: 5 devices; GA expands to 50 devices
		case "enterprise":
			return nil
		default:
			maxDevices = 1
		}
	}

	currentEnrolled, err := st.CountEnrolledDevices(ctx, org.ID)
	if err != nil {
		return fmt.Errorf("count enrolled devices: %w", err)
	}

	if currentEnrolled >= maxDevices {
		if org.LicenseKeyJWT == "" {
			return fmt.Errorf("%w: current enrolled (%d) >= max allowed (%d) for Early Access. To connect more than 5 devices, please activate an Enterprise or Design Partner license key in Organization & License",
				ErrDeviceLimitReached, currentEnrolled, maxDevices)
		}
		return fmt.Errorf("%w: current enrolled (%d) >= max allowed (%d) on '%s' tier. Please upgrade or expand your license quota",
			ErrDeviceLimitReached, currentEnrolled, maxDevices, org.LicenseTier)
	}

	return nil
}
