package pkg

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
)

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=32,alphanum"`
	Email    string `json:"email"    binding:"required,email,max=254"`
	Password string `json:"password" binding:"required,min=8,max=72"`
}

func GenerateHash(password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func CreateUserInDB(db *sqlx.DB, username string, email string, hash string) error {
	query := `
		INSERT INTO users (user_name, user_email, password_hash)
		VALUES ($1, $2, $3)
	`

	_, err := db.Exec(query, username, email, hash)
	if err != nil {
		return err
	}

	return nil
}

func RegisterUser(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RegisterRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			log.Println(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid data"})
			return
		}

		req.Username = strings.ToLower(req.Username)
		req.Email = strings.ToLower(req.Email)

		usernameAvailable, err := CheckDBForUsernameAvailability(db, req.Username)
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "internal error"})
			return
		}

		emailAvailable, err := CheckDBForEmailAvailability(db, req.Email)
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "internal error"})
			return
		}

		if !usernameAvailable {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username already in use"})
			return
		}

		if !emailAvailable {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email already in use"})
			return
		}

		hash, err := GenerateHash(req.Password)
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "internal error"})
			return
		}

		err = CreateUserInDB(db, req.Username, req.Email, string(hash))
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "internal error"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"message": "registration successful",
		})
	}
}

func CheckDBForUsernameAvailability(db *sqlx.DB, value string) (bool, error) {
	query := `
			SELECT EXISTS (
				SELECT 1 FROM users WHERE user_name = $1
			)
	`
	var exists bool
	if err := db.Get(&exists, query, value); err != nil {
		log.Println(err)
		return false, err
	}
	return !exists, nil

}

func CheckDBForEmailAvailability(db *sqlx.DB, value string) (bool, error) {
	query := `
			SELECT EXISTS (
				SELECT 1 FROM users WHERE user_email = $1
			)
	`
	var exists bool
	if err := db.Get(&exists, query, value); err != nil {
		log.Println(err)
		return false, err
	}
	return !exists, nil

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

		if available, err := CheckDBForUsernameAvailability(db, username); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Internal error",
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"available": available,
			})
		}
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

		if available, err := CheckDBForEmailAvailability(db, email); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Internal error",
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"available": available,
			})
		}
	}
}

func LoginUser(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {

	}
}
