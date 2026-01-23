package pkg

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func LogoutHandler(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, err := GetIDFromContext(c, "sessionID")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "auth error"})
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
			log.Printf("[ERROR] Disconnect DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
			return
		}

		err = RemoveWireGuardPeer(clientPublicKey)
		if err != nil {
			log.Printf("[WARN] Failed to remove peer from WireGuard: %v", err)
		}
		query := `
    		WITH deleted_vpn AS (
        	DELETE FROM vpn_configs 
        	WHERE session_id = $1
    		)
    		UPDATE sessions 
    		SET revoked_at = NOW() 
    		WHERE id = $1;
		`
		_, err = db.Exec(query, sessionID)
		if err != nil {
			log.Printf("[ERROR] Failed to logout (DB error): %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
			return
		}
	}
}
