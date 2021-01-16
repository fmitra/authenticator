package authenticator

// Schema contains sql commands to setup the database to work for the authenticator app.
const Schema = `
CREATE TABLE IF NOT EXISTS auth_user (
	id VARCHAR(26) PRIMARY KEY,
	phone VARCHAR(20) UNIQUE NULL,
	email VARCHAR(255) UNIQUE NULL,
	password VARCHAR(60) NOT NULL,
	tfa_secret VARCHAR(70) NOT NULL,
	is_sms_otp_allowed BOOLEAN DEFAULT false,
	is_email_otp_allowed BOOLEAN DEFAULT false,
	is_totp_allowed BOOLEAN DEFAULT false,
	is_device_allowed BOOLEAN DEFAULT false,
	is_verified BOOLEAN DEFAULT false,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp
);
CREATE TABLE IF NOT EXISTS device (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) REFERENCES auth_user(id) NOT NULL,
	client_id BYTEA NOT NULL,
	public_key BYTEA NOT NULL,
	aaguid BYTEA NOT NULL,
	sign_count INT DEFAULT 0,
	name VARCHAR(30) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp
);
CREATE TABLE IF NOT EXISTS login_history (
	token_id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) REFERENCES auth_user(id) NOT NULL,
	is_revoked BOOLEAN DEFAULT false,
	ip_address VARCHAR(45) NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp
);
`
