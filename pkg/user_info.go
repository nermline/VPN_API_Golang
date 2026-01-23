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
		userID, err := GetIDFromContext(c, "userID")
		if err != nil {
			log.Printf("[ERROR] UserInfoHandler failed: %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		sessionID, err := GetIDFromContext(c, "sessionID")
		if err != nil {
			log.Printf("[ERROR] UserInfoHandler failed: %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		query := `SELECT * FROM users WHERE id = $1`
		user := classes.User{}
		err = db.Get(&user, query, userID)
		if err != nil {
			log.Printf("[ERROR] UserInfoHandler failed: %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
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
