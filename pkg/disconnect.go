package pkg

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func DisconnectHandler(wg *wgctrl.Client, config *Config, db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, err := GetIDFromContext(c, "sessionID")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			log.Printf("[ERROR] %v", err)
			return
		}

		var clientPublicKey string
		queryGet := `SELECT client_public_key FROM vpn_configs WHERE session_id = $1`
		err = db.Get(&clientPublicKey, queryGet, sessionID)

		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusOK, gin.H{"status": "disconnected"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			log.Printf("[ERROR] Delete disconnected peer in DB failed: %v", err)
			return
		}
		err = RemoveWireGuardPeer(wg, config, clientPublicKey)
		if err != nil {
			log.Printf("[ERROR] Failed to remove peer from WireGuard: %v", err)
		}

		_, err = db.Exec("DELETE FROM vpn_configs WHERE session_id = $1", sessionID)
		if err != nil {
			log.Printf("[ERROR] Failed to delete config from DB: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "disconnected"})
		log.Printf("[LOG] Session %v disconnected, IP released", sessionID)
	}
}
