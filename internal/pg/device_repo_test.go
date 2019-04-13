package pg

import (
	"context"
	"database/sql"
	"testing"
	"time"

	auth "github.com/fmitra/authenticator"
)

const publicKey = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDLusYAiew7pKRUoLoM6p8+EjBc
5PEaDIrQ5RhtYk2GhpH1PXx02IJRQj/5+1h/DbKmckQkFYNYY9AQBWu1qjTT0KVj
c4Chlue7UxY7IhfFjlHRYxD3CRBBS1EqDC/cCv9QYLsxShn4EhfYelUOV4QDEHrS
vbgxw/pVTSIPc2Y/sQIDAQAB
-----END PUBLIC KEY-----
`

func TestDeviceRepository_Create(t *testing.T) {
	c, err := NewTestClient("device_repo_create_test")
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer DropTestDB(c, "device_repo_create_test")

	ctx := context.Background()
	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		AuthReq:   auth.RequirePassword,
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	device := auth.Device{
		UserID:    user.ID,
		ClientID:  "372b0969c35944209ca7adb5e617365c",
		PublicKey: publicKey,
		Name:      "U2F Key",
	}
	err = c.Device().Create(ctx, &device)
	if err != nil {
		t.Fatal("failed to create device:", err)
	}

	now := time.Now()
	if (now.Sub(device.CreatedAt)).Seconds() > 1 {
		t.Errorf("%s is not a valid time generated for CreatedAt", device.CreatedAt)
	}
	if (now.Sub(device.UpdatedAt)).Seconds() > 1 {
		t.Errorf("%s is not a valid timestamp for UpdatedAt", device.UpdatedAt)
	}

	if device.ID == "" {
		t.Errorf("device ID not set")
	}
}

func TestDeviceRepository_ByID(t *testing.T) {
	c, err := NewTestClient("device_repo_byid_test")
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer DropTestDB(c, "device_repo_byid_test")

	ctx := context.Background()
	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		AuthReq:   auth.RequirePassword,
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	device := auth.Device{
		UserID:    user.ID,
		ClientID:  "client-id",
		PublicKey: publicKey,
		Name:      "U2F Key",
	}
	err = c.Device().Create(ctx, &device)
	if err != nil {
		t.Fatal("failed to create device:", err)
	}

	deviceB, err := c.Device().ByID(ctx, device.ID)
	if err != nil {
		t.Error("failed to retrieve device:", err)
	}
	if deviceB.ID != device.ID {
		t.Errorf("device IDs do not match: want %s got %s", device.ID, deviceB.ID)
	}
}

func TestDeviceRepository_ByUserID(t *testing.T) {
	c, err := NewTestClient("device_repo_by_userid_test")
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer DropTestDB(c, "device_repo_by_userid_test")

	ctx := context.Background()
	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		AuthReq:   auth.RequirePassword,
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	totalDevices := 3
	for i := 0; i < totalDevices; i++ {
		device := auth.Device{
			UserID:    user.ID,
			ClientID:  "372b0969c35944209ca7adb5e617365c",
			PublicKey: publicKey,
			Name:      "U2F Key",
		}
		err = c.Device().Create(ctx, &device)
		if err != nil {
			t.Error("failed to create device:", err)
		}
	}

	devices, err := c.Device().ByUserID(ctx, user.ID)
	if err != nil {
		t.Fatal("failed to retrieve devices:", err)
	}

	if len(devices) != totalDevices {
		t.Errorf("incorrect number of devices: want %v got %v", totalDevices, len(devices))
	}
}

func TestDeviceRepository_ByClientID(t *testing.T) {
	c, err := NewTestClient("device_repo_by_client_test")
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer DropTestDB(c, "device_repo_by_client_test")

	ctx := context.Background()
	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		AuthReq:   auth.RequirePassword,
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	clientID := "372b0969c35944209ca7adb5e617365c"
	device := auth.Device{
		UserID:    user.ID,
		ClientID:  clientID,
		PublicKey: publicKey,
		Name:      "U2F Key",
	}
	err = c.Device().Create(ctx, &device)
	if err != nil {
		t.Fatal("failed to create device:", err)
	}

	deviceB, err := c.Device().ByClientID(ctx, user.ID, clientID)
	if err != nil {
		t.Error("failed to retrieve device:", err)
	}
	if deviceB.ID != device.ID {
		t.Errorf("device IDs do not match: want %s got %s", device.ID, deviceB.ID)
	}
}

func TestDeviceRepository_Update(t *testing.T) {
	c, err := NewTestClient("device_repo_update_test")
	if err != nil {
		t.Fatal("failed to create test database:", err)
	}
	defer DropTestDB(c, "device_repo_update_test")

	ctx := context.Background()
	user := auth.User{
		Password:  "swordfish",
		TFASecret: "tfa_secret",
		AuthReq:   auth.RequirePassword,
		Email: sql.NullString{
			String: "jane@example.com",
			Valid:  true,
		},
	}
	err = c.User().Create(ctx, &user)
	if err != nil {
		t.Fatal("failed to create user:", err)
	}

	clientID := "372b0969c35944209ca7adb5e617365c"
	device := auth.Device{
		UserID:    user.ID,
		ClientID:  clientID,
		PublicKey: publicKey,
		Name:      "U2F Key",
	}
	err = c.Device().Create(ctx, &device)
	if err != nil {
		t.Fatal("failed to create device:", err)
	}

	client, err := c.NewWithTransaction(ctx)
	if err != nil {
		t.Fatal("failed to start transaction:", err)
	}

	entity, err := client.WithAtomic(func() (interface{}, error) {
		device, err := client.Device().GetForUpdate(ctx, device.ID)
		if err != nil {
			return nil, err
		}

		device.Name = "New U2F Key"
		err = client.Device().Update(ctx, device)
		if err != nil {
			return nil, err
		}
		return device, nil
	})
	if err != nil {
		t.Fatal("failed to update device:", err)
	}

	updatedDevice := entity.(*auth.Device)
	if updatedDevice.Name != "New U2F Key" {
		t.Errorf("device name is not updated: want %s got %s",
			"New U2F Key", updatedDevice.Name)
	}
	if updatedDevice.ID != device.ID {
		t.Errorf("device IDs do not match: want %s got %s",
			device.ID, updatedDevice.ID)
	}
}
