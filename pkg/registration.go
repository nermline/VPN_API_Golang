package pkg

import (
	"errors"
	"log"
	"net/http"
	"regexp"
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

type RegisterResponse struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type User struct {
	Username string
	Email    string
	Password string
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

func ValidateUserData(user User) error {
	user.Username = strings.TrimSpace(user.Username)
	user.Email = strings.TrimSpace(user.Email)
	user.Password = strings.TrimSpace(user.Password)
	if user.Username == "" || user.Email == "" || user.Password == "" {
		return errors.New("username, email and password are required")
	}

	emailRegex := `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
	if !regexp.MustCompile(emailRegex).MatchString(user.Email) {
		return errors.New("invalid email format")
	}

	if len(user.Password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	return nil
}

func CheckUsernameExists(db *sqlx.DB, user User) error {
	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE username = $1
		)
	`

	var exists bool
	if err := db.Get(&exists, query, user.Username); err != nil {
		return err
	}

	if exists {
		return errors.New("username already taken")
	}

	return nil
}

func CheckEmailExists(db *sqlx.DB, user User) error {
	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE email = $1
		)
	`

	var exists bool
	if err := db.Get(&exists, query, user.Email); err != nil {
		return err
	}

	if exists {
		return errors.New("email already taken")
	}

	return nil
}

func HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func InsertUser(db *sqlx.DB, user User, hashedPassword string) (int, error) {
	query := `
		INSERT INTO users (username, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id;
	`
	var newID int
	err := db.QueryRow(query, user.Username, user.Email, hashedPassword).Scan(&newID)
	if err != nil {
		return 0, err
	}
	return newID, nil
}

func RegisterHandler(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {

		var req RegisterRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			log.Printf("[WARN] Invalid request body: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		user := User{
			Username: req.Username,
			Email:    req.Email,
			Password: req.Password,
		}

		if err := ValidateUserData(user); err != nil {
			log.Printf("[WARN] Validation failed for username=%s: %v", user.Username, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := CheckUsernameExists(db, user); err != nil {
			if err.Error() == "username already taken" {
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}
			log.Printf("[WARN] CheckUsernameExists failed for username=%s: %v", user.Username, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		if err := CheckEmailExists(db, user); err != nil {
			if err.Error() == "email already taken" {
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}
			log.Printf("[WARN] CheckEmailExists failed for email=%s: %v", user.Email, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		hashedPassword, err := HashPassword(user.Password)
		if err != nil {
			log.Printf("[ERROR] Password hashing failed for username=%s: %v", user.Username, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		newID, err := InsertUser(db, user, hashedPassword)
		if err != nil {
			log.Printf("[ERROR] InsertUser failed for username=%s, email=%s: %v", user.Username, user.Email, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		c.JSON(http.StatusCreated, RegisterResponse{
			ID:       newID,
			Username: user.Username,
			Email:    user.Email,
		})
		log.Printf("[LOG] User %s created successfully!", user.Username)

	}
}
