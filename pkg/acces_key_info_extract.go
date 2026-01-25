package pkg

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

func GetIDFromContext(c *gin.Context, id string) (int, error) {
	IDRaw, exists := c.Get(id)
	if !exists {
		return 0, fmt.Errorf("GetIDFromContext: %v isn't valid ID type", id)
	}

	IDFloat, ok := IDRaw.(float64)
	if !ok {
		if IDInt, okInt := IDRaw.(int); okInt {
			IDFloat = float64(IDInt)
		} else {
			return 0, fmt.Errorf("GetIDFromContext: Failed to convert %v to float", IDRaw)
		}
	}

	ID := int(IDFloat)

	return ID, nil
}
