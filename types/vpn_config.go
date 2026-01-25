package types

import "time"

type VPNConfig struct {
	ID              int       `db:"id"`
	SessionID       int       `db:"session_id"`
	InternalIP      string    `db:"internal_ip"`
	ClientPublicKey string    `db:"client_public_key"`
	CreatedAt       time.Time `db:"created_at"`
}
