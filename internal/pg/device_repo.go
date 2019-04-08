package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/oklog/ulid"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

type DeviceRepository struct {
	client *Client
}

func (r *DeviceRepository) ByID(ctx context.Context, deviceID string) (*auth.Device, error) {
	return r.get(ctx, "byID", deviceID)
}

func (r *DeviceRepository) ByClientID(ctx context.Context, userID, clientID string) (*auth.Device, error) {
	return r.get(ctx, "byClientID", userID, clientID)
}

func (r *DeviceRepository) ByUserID(ctx context.Context, userID string) ([]*auth.Device, error) {
	rows, err := r.client.db.QueryContext(ctx, r.client.deviceQ["byUserID"], userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := make([]*auth.Device, 0)
	for rows.Next() {
		device := auth.Device{}
		err := rows.Scan(
			&device.ID, &device.UserID, &device.ClientID, &device.PublicKey, &device.Name,
			&device.CreatedAt, &device.UpdatedAt,
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

func (r *DeviceRepository) Create(ctx context.Context, device *auth.Device) error {
	entropy := ulid.Monotonic(r.client.rand, 0)
	deviceID, err := ulid.New(ulid.Now(), entropy)
	if err != nil {
		return errors.Wrap(err, "cannot generate unique device ID")
	}

	device.ID = deviceID.String()
	row := r.client.db.QueryRowContext(
		ctx,
		r.client.deviceQ["insert"],
		device.ID,
		device.UserID,
		device.ClientID,
		device.PublicKey,
		device.Name,
	)
	err = row.Scan(
		&device.CreatedAt,
		&device.UpdatedAt,
	)
	return err
}

func (r *DeviceRepository) Update(ctx context.Context, device *auth.Device) error {
	if r.client.tx == nil {
		return fmt.Errorf("cannot update user outside of transaction")
	}

	currentTime := time.Now().UTC()
	device.UpdatedAt = currentTime

	res, err := r.client.tx.ExecContext(
		ctx,
		r.client.deviceQ["update"],
		device.ID,
		device.ClientID,
		device.PublicKey,
		device.Name,
		device.UpdatedAt,
	)
	if err != nil {
		return err
	}

	updatedRows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if updatedRows != 1 {
		return fmt.Errorf("wrong number of devices updated: %d", updatedRows)
	}
	return nil
}

func (r *DeviceRepository) GetForUpdate(ctx context.Context, deviceID string) (*auth.Device, error) {
	device := auth.Device{}
	row := r.client.tx.QueryRowContext(ctx, r.client.deviceQ["forUpdate"], deviceID)
	err := row.Scan(
		&device.ID, &device.UserID, &device.ClientID, &device.PublicKey, &device.Name,
		&device.CreatedAt, &device.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &device, nil
}

func (r *DeviceRepository) get(ctx context.Context, queryKey string, values ...interface{}) (*auth.Device, error) {
	device := auth.Device{}
	row := r.client.db.QueryRowContext(ctx, r.client.deviceQ[queryKey], values...)
	err := row.Scan(
		&device.ID, &device.UserID, &device.ClientID, &device.PublicKey, &device.Name,
		&device.CreatedAt, &device.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &device, nil
}
