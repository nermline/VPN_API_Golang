package pkg

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/nermline/VPN_API_Golang/types"
	"golang.org/x/crypto/bcrypt"
)

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=32,alphanum"`
	Email    string `json:"email"    binding:"required,email,max=254"`
	Password string `json:"password" binding:"required,min=8,max=72"`
}

func ValidateRegistrationData(user types.User) error {
	user.Username = strings.TrimSpace(user.Username)
	user.Email = strings.TrimSpace(user.Email)
	user.Password = strings.TrimSpace(user.Password)
	if user.Username == "" {
		return errors.New("ValidateRegistrationData: Username is empty")
	}
	if user.Email == "" {
		return errors.New("ValidateRegistrationData: Email is empty")
	}
	if user.Password == "" {
		return errors.New("ValidateRegistrationData: Password is empty")
	}

	emailRegex := `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
	if !regexp.MustCompile(emailRegex).MatchString(user.Email) {
		return errors.New("ValidateRegistrationData: Invalid email format")
	}

	if len(user.Password) < 8 {
		return errors.New("ValidateRegistrationData: Password less than 8 characters")
	}

	return nil
}

func HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("HashPassword: %v", err)
	}
	return string(hashed), nil
}

func InsertUser(db *sqlx.DB, user types.User) (int, error) {
	query := `
		INSERT INTO users (username, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id;
	`
	var newID int
	err := db.QueryRow(query, user.Username, user.Email, user.Password).Scan(&newID)
	if err != nil {
		return 0, fmt.Errorf("InsertUser: %v", err)
	}
	return newID, nil
}

func RegisterHandler(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {

		var req RegisterRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			log.Printf("[ERROR] Invalid request body: %v | Client: %v", err, c.ClientIP())
			return
		}

		user := types.User{
			ID:       0,
			Username: req.Username,
			Email:    req.Email,
			Password: req.Password,
		}

		if err := ValidateRegistrationData(user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			log.Printf("[ERROR] Validation failed: %v | Client: %v", err, c.ClientIP())
			return
		}

		hashedPassword, err := HashPassword(user.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			log.Printf("[ERROR] Password hashing failed: %v | Client: %v", err, c.ClientIP())
			return
		}

		user.Password = hashedPassword

		newID, err := InsertUser(db, user)
		if err != nil {
			var pqErr *pq.Error
			if errors.As(err, &pqErr) && pqErr.Code == "23505" {
				if strings.Contains(pqErr.Constraint, "email") {
					c.JSON(http.StatusConflict, gin.H{"error": "email already in use"})
					return
				}
				if strings.Contains(pqErr.Constraint, "username") {
					c.JSON(http.StatusConflict, gin.H{"error": "username already in use"})
					return
				}
			}

			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			log.Printf("[ERROR] Failed to insert user: %v", err)
			return
		}

		user.ID = newID

		c.JSON(http.StatusCreated, gin.H{
			"message": "account created",
		})

		log.Printf("[LOG] User \"%v\" (%v) created successfully!", user.Username, user.Email)
	}
}
