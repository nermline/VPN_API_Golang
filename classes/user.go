package classes

import "github.com/google/uuid"

type User struct {
	UserID             uuid.UUID
	UserName           string
	UserEmail          string
	PasswordHash       string
	AdblockMembership  bool
	StaticIpMembership bool
	TelegramOnlyMode   bool
	IsCreator          bool
	Devices            []Device
}
