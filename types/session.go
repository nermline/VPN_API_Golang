package types

import "time"

type Session struct {
	ID           int        `db:"id"`
	UserID       int        `db:"user_id"`
	DeviceID     int        `db:"device_id"`
	RefreshToken string     `db:"refresh_token"`
	CreatedAt    time.Time  `db:"created_at"`
	ExpiresAt    time.Time  `db:"expires_at"`
	Revoked      *time.Time `db:"revoked_at"`
}
