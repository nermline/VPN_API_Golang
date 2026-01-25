package pkg

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/nermline/VPN_API_Golang/types"
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

	if req.Username == "" {
		return errors.New("ValidateLoginData: Username is empty")
	}
	if req.DeviceName == "" {
		return errors.New("ValidateLoginData: Device name is empty")
	}
	if req.OS == "" {
		return errors.New("ValidateLoginData: OS name is empty")
	}
	if req.DeviceUUID == "" {
		return errors.New("DeviceUUID is empty")
	}

	if len(req.DeviceName) > 30 {
		return errors.New("Device name too long")
	}
	if len(req.OS) > 30 {
		return errors.New("OS name too long")
	}

	if !uuidRegex.MatchString(req.DeviceUUID) {
		return errors.New("Invalid uuid format")
	}
	return nil
}

func CheckUser(db *sqlx.DB, req LoginRequest) (*types.User, error) {
	query := `SELECT * FROM users WHERE username = $1`
	user := types.User{}
	err := db.Get(&user, query, req.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("Credentials failed")
		}
		return nil, fmt.Errorf("CheckUser: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		return nil, errors.New("Credentials failed")
	}
	return &user, nil
}

func IdentifyDevice(db *sqlx.DB, req LoginRequest) (*types.Device, error) {
	const query = `SELECT * FROM devices WHERE device_uid = $1`
	var device types.Device
	err := db.Get(&device, query, req.DeviceUUID)
	if err != nil {
		if err == sql.ErrNoRows {
			return &types.Device{
				ID:        0,
				UUID:      req.DeviceUUID,
				Name:      req.DeviceName,
				OS:        req.OS,
				CreatedAt: time.Now(),
				LastSeen:  time.Now(),
			}, nil
		}
		return nil, fmt.Errorf("IdentifyDevice: %v", err)
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
		return "", fmt.Errorf("GenerateRefreshToken: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func CreateSession(db *sqlx.DB, user types.User, device types.Device) (*types.Session, error) {
	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("CreateSession: %v", err)
	}

	tokenExpiresAt := time.Now().Add(180 * 24 * time.Hour)

	session := types.Session{
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

func GetJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Panic("[CRITICAL] ADD ENV VARIABLE \"JWT_SECRET\" RIGHT NOW!")
	}
	return []byte(secret)
}

func GenerateAccessToken(user types.User, session types.Session, secretKey []byte) (string, int, error) {
	tokenLifeTime := 15 * time.Second

	claims := jwt.MapClaims{
		"exp":        time.Now().Add(tokenLifeTime).Unix(),
		"iat":        time.Now().Unix(),
		"user_id":    user.ID,
		"session_id": session.ID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", 0, fmt.Errorf("GenerateAccessToken: %v", err)
	}

	return signedToken, int(tokenLifeTime.Seconds()), nil
}

func WriteLoginChanges(db *sqlx.DB, device *types.Device, session *types.Session) error {
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
			return fmt.Errorf("WriteLoginChanges: %v", err)
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
			return fmt.Errorf("WriteLoginChanges: %v", err)
		}
	}

	return nil
}

func LoginHandler(db *sqlx.DB, secretKey []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			log.Printf("[ERROR] Invalid request body: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		if err := ValidateLoginData(&req); err != nil {
			log.Printf("[ERROR] Validation failed for username=%s: %v", req.Username, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		user, err := CheckUser(db, req)
		if err != nil {
			if err.Error() == "credentials failed" {
				log.Printf("[ERROR] Auth failed for username=%s", req.Username)
				c.JSON(http.StatusBadRequest, gin.H{"error": "username or password failed"})
				return
			}
			log.Printf("[ERROR] Auth DB error for %s: %v", req.Username, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		device, err := IdentifyDevice(db, req)
		if err != nil {
			log.Printf("[ERROR] %v: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		session, err := CreateSession(db, *user, *device)
		if err != nil {
			log.Printf("[ERROR] %v: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		if err := WriteLoginChanges(db, device, session); err != nil {
			log.Printf("[ERROR] %v: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		accessToken, accessTokenLifeTime, err := GenerateAccessToken(*user, *session, secretKey)
		if err != nil {
			log.Printf("[ERROR] %v: ", err)
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
