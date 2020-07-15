package totpapi

// Response is a success response with an embedded TOTP string.
type Response struct {
	TOTP string `json:"totp"`
}
