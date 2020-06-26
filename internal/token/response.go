package token

// Response ensures consistent formatting for JSON APIs.
type Response struct {
	ClientID string `json:"clientID"`
	Token    string `json:"code"`
}
