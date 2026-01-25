package pkg

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func LogoutHandler(wg *wgctrl.Client, config *Config, db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, err := GetIDFromContext(c, "sessionID")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid or expired token"})
			log.Printf("[ERROR] %v: ", err)
			return
		}

		var clientPublicKey string
		queryGet := `SELECT client_public_key FROM vpn_configs WHERE session_id = $1`
		err = db.Get(&clientPublicKey, queryGet, sessionID)
		if err != nil {
			log.Printf("[ERROR] Failed to find public key of session %v: %v", sessionID, err)
		}

		err = RemoveWireGuardPeer(wg, config, clientPublicKey)
		if err != nil {
			log.Printf("[ERROR] %v: ", err)
		}

		_, err = db.Exec("DELETE FROM vpn_configs WHERE session_id = $1", sessionID)
		if err != nil {
			log.Printf("[ERROR] Failed to delete config from DB: %v", err)
		}

		query := `UPDATE sessions 	
			      SET revoked_at = NOW() 
			      WHERE id = $1 AND expires_at > NOW() AND revoked_at IS NULL
        `
		_, err = db.Exec(query, sessionID)
		if err != nil {
			log.Printf("[ERROR] Failed to revoke session %v: %v", sessionID, err)
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "logout",
		})
	}
}
