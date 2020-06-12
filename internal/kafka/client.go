// Package kafka provides a client for Kafka.
package kafka

import (
	kafkaLib "github.com/segmentio/kafka-go"
)

// Topics
const (
	topicOTP = "authenticator.messages.otp"
)

// Client contains a pair of Kafka reader and writers
// for every topic we are interested in.
type Client struct {
	OTPReader *kafkaLib.Reader
	OTPWriter *kafkaLib.Writer
}

// NewClient returns a new Client.
func NewClient(brokers []string) *Client {
	return &Client{
		OTPReader: newReader(brokers, topicOTP),
		OTPWriter: newWriter(brokers, topicOTP),
	}
}

func newReader(brokers []string, topic string) *kafkaLib.Reader {
	return kafkaLib.NewReader(kafkaLib.ReaderConfig{
		Brokers:   brokers,
		Topic:     topic,
		Partition: 0,
		MinBytes:  10e3,
		MaxBytes:  10e6,
	})
}

func newWriter(brokers []string, topic string) *kafkaLib.Writer {
	return kafkaLib.NewWriter(kafkaLib.WriterConfig{
		Brokers: brokers,
		Topic:   topic,
		// Compatibility with Kafka sarama client.
		Balancer: &kafkaLib.Hash{},
		// kafka-go defaults the capacity to 100.
		QueueCapacity: 200,
	})
}
