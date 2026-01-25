package pkg

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/nermline/VPN_API_Golang/classes"
	"golang.org/x/crypto/bcrypt"
)

var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type LoginRequest struct {
	Username   string `json:"username"    binding:"required,min=3,max=32,alphanum"`
	Password   string `json:"password"    binding:"required,min=8,max=72"`
	DeviceName string `json:"device_name" binding:"required"`
	OS         string `json:"os"          binding:"required"`
	DeviceUUID string `json:"device_uid"  binding:"required"`
}

type LoginResponse struct {
	AccessToken        string `json:"access_token"`
	AccessTokenExpires int    `json:"expires_in"`
	RefreshToken       string `json:"refresh_token"`
}

func ValidateLoginData(req *LoginRequest) error {
	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)

	if req.Username == "" || req.Password == "" || req.DeviceName == "" || req.OS == "" || req.DeviceUUID == "" {
		return errors.New("user credentials and device info are required")
	}
	if len(req.DeviceName) > 30 {
		return errors.New("device name too long")
	}
	if len(req.OS) > 30 {
		return errors.New("os name too long")
	}

	if !uuidRegex.MatchString(req.DeviceUUID) {
		return errors.New("invalid uuid format")
	}
	return nil
}

func CheckUser(db *sqlx.DB, req LoginRequest) (*classes.User, error) {
	query := `SELECT * FROM users WHERE username = $1`
	user := classes.User{}
	err := db.Get(&user, query, req.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("credentials failed")
		}
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		return nil, errors.New("credentials failed")
	}
	return &user, nil
}

func IdentifyDevice(db *sqlx.DB, req LoginRequest) (*classes.Device, error) {
	const query = `SELECT * FROM devices WHERE device_uid = $1`
	var device classes.Device
	err := db.Get(&device, query, req.DeviceUUID)
	if err != nil {
		if err == sql.ErrNoRows {
			return &classes.Device{
				ID:        0,
				UUID:      req.DeviceUUID,
				Name:      req.DeviceName,
				OS:        req.OS,
				CreatedAt: time.Now(),
				LastSeen:  time.Now(),
			}, nil
		}
		return nil, err
	}

	device.Name = req.DeviceName
	device.OS = req.OS
	device.LastSeen = time.Now()
	return &device, nil
}

func GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func CreateSession(db *sqlx.DB, user classes.User, device classes.Device) (*classes.Session, error) {
	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	tokenExpiresAt := time.Now().Add(180 * 24 * time.Hour)

	session := classes.Session{
		ID:           0,
		UserID:       user.ID,
		DeviceID:     device.ID,
		RefreshToken: refreshToken,
		CreatedAt:    time.Now(),
		ExpiresAt:    tokenExpiresAt,
		Revoked:      nil,
	}
	return &session, nil
}

func getJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return []byte("JWT_SECRET_KEY") // Тільки для дева!
	}
	return []byte(secret)
}

func GenerateAccessToken(user classes.User, session classes.Session) (string, int, error) {
	tokenLifeTime := 15 * time.Second
	secretKey := getJWTSecret()

	claims := jwt.MapClaims{
		"exp":        time.Now().Add(tokenLifeTime).Unix(),
		"iat":        time.Now().Unix(),
		"user_id":    user.ID,
		"session_id": session.ID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", 0, err
	}

	return signedToken, int(tokenLifeTime.Seconds()), nil
}

func WriteLoginChanges(db *sqlx.DB, device *classes.Device, session *classes.Session) error {
	var query string
	var args []interface{}

	if device.ID != 0 {
		query = `
            WITH upd_device AS (
                UPDATE devices 
                SET last_seen = NOW(), device_name = $6, os = $7
                WHERE id = $1
            ),
            revoke_old_sessions AS (
                UPDATE sessions 
                SET revoked_at = NOW() 
                WHERE device_id = $1 
                  AND revoked_at IS NULL
            )
            INSERT INTO sessions (user_id, device_id, refresh_token, created_at, expires_at)
            VALUES ($2, $1, $3, $4, $5)
            RETURNING id;
        `
		args = []interface{}{
			device.ID,
			session.UserID,
			session.RefreshToken,
			session.CreatedAt,
			session.ExpiresAt,
			device.Name,
			device.OS,
		}

		if err := db.QueryRow(query, args...).Scan(&session.ID); err != nil {
			return err
		}

	} else {
		query = `
            WITH new_device AS (
                INSERT INTO devices (device_uid, device_name, os, created_at, last_seen)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id
            )
            INSERT INTO sessions (user_id, device_id, refresh_token, created_at, expires_at)
            SELECT $6, id, $7, $8, $9 FROM new_device
            RETURNING id, device_id;
        `
		args = []interface{}{
			device.UUID,
			device.Name,
			device.OS,
			device.CreatedAt,
			device.LastSeen,
			session.UserID,
			session.RefreshToken,
			session.CreatedAt,
			session.ExpiresAt,
		}

		if err := db.QueryRow(query, args...).Scan(&session.ID, &device.ID); err != nil {
			return err
		}
	}

	return nil
}

func LoginHandler(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			log.Printf("[WARN] Invalid request body: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		if err := ValidateLoginData(&req); err != nil {
			log.Printf("[WARN] Validation failed for username=%s: %v", req.Username, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		user, err := CheckUser(db, req)
		if err != nil {
			if err.Error() == "credentials failed" {
				log.Printf("[WARN] Auth failed for username=%s", req.Username)
				c.JSON(http.StatusBadRequest, gin.H{"error": "username or password failed"})
				return
			}
			log.Printf("[ERROR] DB error checking user %s: %v", req.Username, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		device, err := IdentifyDevice(db, req)
		if err != nil {
			log.Printf("[ERROR] IdentifyDevice failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		session, err := CreateSession(db, *user, *device)
		if err != nil {
			log.Printf("[ERROR] CreateSession failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		if err := WriteLoginChanges(db, device, session); err != nil {
			log.Printf("[ERROR] WriteLoginChanges failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		accessToken, accessTokenLifeTime, err := GenerateAccessToken(*user, *session)
		if err != nil {
			log.Printf("[ERROR] GenerateAccessToken failed: %v", err)
			// Тут можна було б теоретично відкотити транзакцію, але в нас її немає.
			// Сесія залишиться в базі, але юзер не отримає токен. Це не критично, просто "мертва" сесія.
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		c.JSON(http.StatusCreated, LoginResponse{
			AccessToken:        accessToken,
			AccessTokenExpires: accessTokenLifeTime,
			RefreshToken:       session.RefreshToken,
		})
		log.Printf("[LOG] Session id %v created successfully for user %v", session.ID, user.ID)
	}
}
