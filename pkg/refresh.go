package pkg

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/nermline/VPN_API_Golang/classes"
)

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func GetFullSessionInfo(db *sqlx.DB, refreshToken string) (*classes.Session, *classes.User, *classes.Device, error) {
	query := `
		SELECT 
			s.id, s.user_id, s.device_id, s.refresh_token, s.created_at, s.expires_at, s.revoked_at,
			u.id, u.username, u.password_hash,
			d.id, d.device_uid, d.device_name, d.os, d.created_at, d.last_seen
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		JOIN devices d ON s.device_id = d.id
		WHERE s.refresh_token = $1
	`

	var session classes.Session
	var user classes.User
	var device classes.Device

	row := db.QueryRow(query, refreshToken)

	err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.DeviceID,
		&session.RefreshToken,
		&session.CreatedAt,
		&session.ExpiresAt,
		&session.Revoked,

		&user.ID,
		&user.Username,
		&user.Password,

		&device.ID,
		&device.UUID,
		&device.Name,
		&device.OS,
		&device.CreatedAt,
		&device.LastSeen,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil, errors.New("session not found")
		}
		return nil, nil, nil, err
	}

	return &session, &user, &device, nil
}

func RotateRefreshToken(session classes.Session) (*classes.Session, error) {
	if session.Revoked != nil {
		return nil, errors.New("session revoked")
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, errors.New("refresh token expired")
	}

	newToken, err := GenerateRefreshToken()
	if err != nil {
		return nil, err
	}
	session.RefreshToken = newToken
	session.CreatedAt = time.Now()
	session.ExpiresAt = time.Now().Add(180 * 24 * time.Hour)
	return &session, nil
}

func WriteRefreshChanges(db *sqlx.DB, session classes.Session, device classes.Device) error {
	query := `
        WITH upd_device AS (
            UPDATE devices
            SET last_seen = NOW()
            WHERE id = $1
        )
        UPDATE sessions
        SET refresh_token = $2,
            created_at = $3,
            expires_at = $4
        WHERE id = $5;
    `
	_, err := db.Exec(query,
		device.ID,
		session.RefreshToken,
		session.CreatedAt,
		session.ExpiresAt,
		session.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func RefreshHandler(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		session, user, device, err := GetFullSessionInfo(db, req.RefreshToken)
		if err != nil {
			if err.Error() == "session not found" {
				log.Printf("[WARN] GetFullSessionInfo failed for refresh token=%s: %v", req.RefreshToken, err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
				return
			}
			log.Printf("[WARN] GetFullSessionInfo failed for refresh token=%s: %v", req.RefreshToken, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		session, err = RotateRefreshToken(*session)
		if err != nil {
			log.Printf("[WARN] Refresh failed: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
			return
		}

		err = WriteRefreshChanges(db, *session, *device)
		if err != nil {
			log.Printf("[ERROR] WriteRefreshChanges failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		accessToken, expiresIn, err := GenerateAccessToken(*user, *session)
		if err != nil {
			log.Printf("[ERROR] Token generation failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		c.JSON(http.StatusOK, LoginResponse{
			AccessToken:        accessToken,
			AccessTokenExpires: expiresIn,
			RefreshToken:       session.RefreshToken,
		})

		log.Printf("[LOG] Refresh successful for session %v with device %s", session.ID, device.Name)

	}
}
