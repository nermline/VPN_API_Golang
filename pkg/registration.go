package pkg

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=32,alphanum"`
	Email    string `json:"email"    binding:"required,email,max=254"`
	Password string `json:"password" binding:"required,min=8,max=72"`
}

func RegisterUser(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RegisterRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid data"})
			return
		}

		req.Username = strings.ToLower(req.Username)
		req.Email = strings.ToLower(req.Email)

	}
}

func CheckAvailability(db *sqlx.DB, table string, variable string, value string) {
	query := `
			SELECT EXISTS (
				SELECT 1 FROM $1 WHERE $2 = $3
			)
	`

	if err := db.Get(&exists); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database error",
		})
		return
	}

}

func CheckUsernameAvailability(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.Query("username")
		if username == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "username is required",
			})
			return
		}

		CheckAvailability(db, "users", "username", username)
	}
}

func CheckEmailAvailability(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		email := c.Query("email")
		if email == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "email is required",
			})
			return
		}

		CheckAvailability(db, "users", "email", email)

	}
}

func LoginUser(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {

	}
}
