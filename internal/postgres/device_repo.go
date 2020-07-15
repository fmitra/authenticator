package postgres

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

// DeviceRepository is an implementation of auth.DeviceRepository interface.
type DeviceRepository struct {
	client *Client
}

// ByID retrieves a Device with a matching ID.
func (r *DeviceRepository) ByID(ctx context.Context, deviceID string) (*auth.Device, error) {
	return r.get(ctx, "byID", deviceID)
}

// ByClientID retrieves a Device with a matching ClientID.
func (r *DeviceRepository) ByClientID(ctx context.Context, userID string, clientID []byte) (*auth.Device, error) {
	return r.get(ctx, "byClientID", userID, clientID)
}

// ByUserID retrieves all Devices associated with a User.
func (r *DeviceRepository) ByUserID(ctx context.Context, userID string) ([]*auth.Device, error) {
	rows, err := r.client.queryContext(ctx, r.client.deviceQ["byUserID"], userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := make([]*auth.Device, 0)
	for rows.Next() {
		device := auth.Device{}
		err := rows.Scan(
			&device.ID, &device.UserID, &device.ClientID, &device.PublicKey, &device.Name,
			&device.AAGUID, &device.SignCount, &device.CreatedAt, &device.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		devices = append(devices, &device)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return devices, nil
}

// Create persists a new Device to a storage.
func (r *DeviceRepository) Create(ctx context.Context, device *auth.Device) error {
	deviceID, err := ulid.New(ulid.Now(), r.client.entropy)
	if err != nil {
		return errors.Wrap(err, "cannot generate unique device ID")
	}

	device.ID = deviceID.String()
	row := r.client.queryRowContext(
		ctx,
		r.client.deviceQ["insert"],
		device.ID,
		device.UserID,
		device.ClientID,
		device.PublicKey,
		device.Name,
		device.AAGUID,
		device.SignCount,
	)
	err = row.Scan(
		&device.CreatedAt,
		&device.UpdatedAt,
	)
	return err
}

// Update updates a Device in storage.
func (r *DeviceRepository) Update(ctx context.Context, device *auth.Device) error {
	currentTime := time.Now().UTC()
	device.UpdatedAt = currentTime

	res, err := r.client.execContext(
		ctx,
		r.client.deviceQ["update"],
		device.ID,
		device.ClientID,
		device.PublicKey,
		device.Name,
		device.SignCount,
		device.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, "failed to execute update")
	}

	updatedRows, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "failed to check affected rows")
	}
	if updatedRows != 1 {
		return errors.Errorf("wrong number of devices updated: %d", updatedRows)
	}
	return nil
}

// GetForUpdate retrieves a Device to be updated.
func (r *DeviceRepository) GetForUpdate(ctx context.Context, deviceID string) (*auth.Device, error) {
	device := auth.Device{}
	row := r.client.queryRowContext(ctx, r.client.deviceQ["forUpdate"], deviceID)
	err := row.Scan(
		&device.ID, &device.UserID, &device.ClientID, &device.PublicKey, &device.Name,
		&device.AAGUID, &device.SignCount, &device.CreatedAt, &device.UpdatedAt,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrieve record for update")
	}

	return &device, nil
}

// Remove removes a Device associated with a User.
func (r *DeviceRepository) Remove(ctx context.Context, deviceID, userID string) error {
	res, err := r.client.execContext(ctx, r.client.deviceQ["delete"], deviceID, userID)
	if err != nil {
		return errors.Wrap(err, "failed to execute delete")
	}

	removedRows, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "failed to check affected rows")
	}
	if removedRows == 0 {
		return auth.ErrNotFound("device does not exist")
	}
	if removedRows != 1 {
		return errors.Errorf("wrong number of devices removed: %d", removedRows)
	}

	return nil
}

func (r *DeviceRepository) get(ctx context.Context, queryKey string, values ...interface{}) (*auth.Device, error) {
	device := auth.Device{}
	row := r.client.queryRowContext(ctx, r.client.deviceQ[queryKey], values...)
	err := row.Scan(
		&device.ID, &device.UserID, &device.ClientID, &device.PublicKey, &device.Name,
		&device.AAGUID, &device.SignCount, &device.CreatedAt, &device.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &device, nil
}
