package pkg

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/nermline/VPN_API_Golang/types"
)

func UserInfoHandler(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := GetIDFromContext(c, "userID")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			log.Printf("[ERROR] Failed to extract user ID from context: %s | Client: %v", err, c.ClientIP())
			return
		}

		sessionID, err := GetIDFromContext(c, "sessionID")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			log.Printf("[ERROR] Failed to extract user ID from context: %s | Client: %v", err, c.ClientIP())
			return
		}

		query := `SELECT * FROM users WHERE id = $1`
		user := types.User{}
		err = db.Get(&user, query, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			log.Printf("[ERROR] Failed to find user %v: %v | Client: ", userID, err, c.ClientIP())
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"user_id":    user.ID,
			"session_id": sessionID,
			"username":   user.Username,
			"email":      user.Email,
		})
	}
}
