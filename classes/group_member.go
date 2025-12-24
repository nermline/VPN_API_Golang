package classes

import "github.com/google/uuid"

type GroupMember struct {
	UserID  uuid.UUID
	GroupID uuid.UUID
}
