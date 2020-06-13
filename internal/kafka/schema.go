package kafka

// MessageSchema is represents an Avro serialized Message.
const MessageSchema = `
{
	"type": "record",
	"name": "Message",
	"fields": [
        {"name": "delivery", "type": "enum", "symbols": ["phone", "email"]},
		{"name": "delivery", "type": "string"},
		{"name": "content", "type": "string"},
		{"name": "address", "type": "string"},
        {"name": "expires_at", "type": {"type": "long","logicalType": "timestamp-micros"}}
	]
}
`
