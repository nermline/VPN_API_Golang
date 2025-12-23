package api

import "github.com/google/uuid"

type User struct {
	UserID             uuid.UUID
	UserName           string
	UserEmail          string
	PasswordHash       string
	StaticIpMembership bool
	TelegramOnlyMode   bool
	IsCreator          bool
	Devices            []Device
}
