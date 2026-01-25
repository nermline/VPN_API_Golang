package types

import "time"

type Device struct {
	ID        int       `db:"id"`
	UUID      string    `db:"device_uid"`
	Name      string    `db:"device_name"`
	OS        string    `db:"os"`
	CreatedAt time.Time `db:"created_at"`
	LastSeen  time.Time `db:"last_seen"`
}
