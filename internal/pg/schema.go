// Package pg provides implementations of authenticator domain repository interfaces.
package pg

// Schema contains sql commands to setup the database to work for the authenticator app.
// Schema includes extensions and tables which must be created before working with
// repositories.
const Schema = `
CREATE TABLE IF NOT EXISTS auth_user (
	id VARCHAR(26) PRIMARY KEY,
	phone VARCHAR(20) UNIQUE NULL,
	email VARCHAR(255) UNIQUE NULL,
	password VARCHAR(60) NOT NULL,
	tfa_secret VARCHAR(20) NOT NULL,
	auth_req VARCHAR(10) NOT NULL,
	is_verified BOOLEAN DEFAULT false,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp
);
CREATE TABLE IF NOT EXISTS device (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) REFERENCES auth_user(id) NOT NULL,
	client_id VARCHAR(36) NOT NULL,
	public_key TEXT NOT NULL,
	name VARCHAR(30) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp
);
CREATE TABLE IF NOT EXISTS login_history (
	token_id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) REFERENCES auth_user(id) NOT NULL,
	is_revoked BOOLEAN DEFAULT false,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp
);
`
