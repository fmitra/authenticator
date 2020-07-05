package token

// Response ensures consistent formatting for JSON APIs.
type Response struct {
	Token    string `json:"token"`
	ClientID string `json:"clientID,omitempty"`
}
