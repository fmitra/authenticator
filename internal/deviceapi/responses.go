package deviceapi

import (
	"time"

	auth "github.com/fmitra/authenticator"
)

// deviceResponse is the response format for authenticator.Device.
type deviceResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// listResponse is a success response for DeviceAPI.List
type listResponse struct {
	Devices []deviceResponse `json:"devices"`
}

// singleResponse is a success response for a single Device.
type singleResponse struct {
	Device deviceResponse `json:"device"`
}

// Create populates a ResponseList with a list of Devices.
func (r *listResponse) Create(devices []*auth.Device) {
	rd := []deviceResponse{}
	for _, d := range devices {
		rd = append(rd, deviceResponse{
			ID:        d.ID,
			Name:      d.Name,
			CreatedAt: d.CreatedAt,
			UpdatedAt: d.UpdatedAt,
		})
	}
	r.Devices = rd
}

// Create populates fields in a singleResponse.
func (r *singleResponse) Create(device *auth.Device) {
	r.Device.ID = device.ID
	r.Device.Name = device.Name
	r.Device.CreatedAt = device.CreatedAt
	r.Device.UpdatedAt = device.UpdatedAt
}
