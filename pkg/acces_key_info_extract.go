package pkg

import (
	"errors"

	"github.com/gin-gonic/gin"
)

func GetIDFromContext(c *gin.Context, id string) (int, error) {
	IDRaw, exists := c.Get(id)
	if !exists {
		return 0, errors.New("unauthorized")
	}
	IDFloat, ok := IDRaw.(float64)
	if !ok {
		if IDInt, okInt := IDRaw.(int); okInt {
			IDFloat = float64(IDInt)
		} else {
			return 0, errors.New("internal server error")
		}
	}

	ID := int(IDFloat)

	return ID, nil
}
