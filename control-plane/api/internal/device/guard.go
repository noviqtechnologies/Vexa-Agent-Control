package device

import (
	"context"
	"errors"
	"fmt"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

var (
	ErrDeviceLimitReached = errors.New("device enrollment limit reached for current license tier")
)

// CheckDeviceEnrollmentLimit verifies if the organization can enroll another device.
// Developer tier = 1 device, Team tier = 25 devices, Enterprise tier = unlimited (-1).
func CheckDeviceEnrollmentLimit(ctx context.Context, st *store.Store, organizationID string) error {
	if st == nil {
		return nil
	}
	org, err := st.GetOrganization(ctx, organizationID)
	if err != nil {
		return fmt.Errorf("lookup organization license: %w", err)
	}

	maxDevices := org.MaxDevices
	if maxDevices <= 0 && org.LicenseTier == "enterprise" {
		return nil // Unlimited
	}
	if maxDevices <= 0 {
		switch org.LicenseTier {
		case "team":
			maxDevices = 25
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
		return fmt.Errorf("%w: current enrolled (%d) >= max allowed (%d) on '%s' tier",
			ErrDeviceLimitReached, currentEnrolled, maxDevices, org.LicenseTier)
	}

	return nil
}
