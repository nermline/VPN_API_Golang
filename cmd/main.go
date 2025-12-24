package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/nermline/VPN_API_Golang/pkg"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=32,alphanum"`
	Email    string `json:"email"    binding:"required,email,max=254"`
	Password string `json:"password" binding:"required,min=8,max=72"`
}

var ErrUserConflict = errors.New("user already exists")

func isUniqueViolation(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok {
		return pqErr.Code == "23505"
	}
	return false
}

func createUser(username, email, hash string) error {
	query := `
		INSERT INTO users (user_name, user_email, password_hash)
		VALUES ($1, $2, $3)
	`

	_, err := db.Exec(query, username, email, hash)
	if err != nil {
		fmt.Println("DB ERROR:", err) // <--- додано для дебагу
		if isUniqueViolation(err) {
			return ErrUserConflict
		}
		return err
	}

	return nil
}

func Register(c *gin.Context) {
	var req RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid RegisterRequest input"})
		return
	}

	req.Username = strings.ToLower(req.Username)
	req.Email = strings.ToLower(req.Email)

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(req.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal crypto error",
		})
		return
	}

	err = createUser(req.Username, req.Email, string(hash))
	if err != nil {
		if errors.Is(err, ErrUserConflict) {
			c.JSON(http.StatusConflict, gin.H{
				"error": "registration failed",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal create user error",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "registration successful",
	})
}

func main() {
	var path = "/Users/nermline/Data/Programing projects/VPN_API_Golang/config.yaml"
	cfg, err := pkg.LoadConfig(path)
	if err != nil {
		log.Panic(err)
	}
	log.Println("[LOG] Config " + path + " loaded successfully")

	db, err := pkg.NewPostgres(cfg.Postgres)
	if err != nil {
		log.Panic(err)
	}
	log.Println("[LOG] Postgres database \"" + cfg.Postgres.DBName + "\" connected")
	defer db.Close()

	router := gin.Default()
	router.POST("/api/v1/auth/register", pkg.RegisterUser(db))
	router.POST("/api/v1/auth/login", pkg.LoginUser(db))
	router.GET("/api/v1/users/availability", pkg.CheckUsernameAvailability(db))
	router.GET("/api/v1/email/availability", pkg.CheckEmailAvailability(db))
	router.Run()
}
