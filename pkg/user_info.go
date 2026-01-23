package pkg

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/nermline/VPN_API_Golang/classes"
)

func UserInfoHandler(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDRaw, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		userIDFloat, ok := userIDRaw.(float64)
		if !ok {
			if userIDInt, okInt := userIDRaw.(int); okInt {
				userIDFloat = float64(userIDInt)
			} else {
				log.Printf("[ERROR] userID in context is not a number: %T", userIDRaw)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
				return
			}
		}

		userID := int(userIDFloat)
		query := `SELECT * FROM users WHERE id = $1`
		user := classes.User{}
		err := db.Get(&user, query, userID)
		if err != nil {
			log.Printf("[ERROR] UserInfoHandler failed: %T", userIDRaw)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		})
	}
}
