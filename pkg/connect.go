package pkg

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/nermline/VPN_API_Golang/types"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type ConnectRequest struct {
	PublicKey string `json:"public_key" binding:"required,len=44"`
}

type InterfaceConfig struct {
	Address string `json:"address"`
	DNS     string `json:"dns"`
}

type PeerConfig struct {
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
}

type WireguardConfigResponse struct {
	Interface InterfaceConfig `json:"interface"`
	Peer      PeerConfig      `json:"peer"`
}

func UpdateClientKey(tx *sqlx.Tx, configID int, newKey string) error {
	_, err := tx.Exec("UPDATE vpn_configs SET client_public_key = $1 WHERE id = $2", newKey, configID)
	return fmt.Errorf("UpdateClientKey: ", err)
}

func WriteConnectChanges(tx *sqlx.Tx, config *types.VPNConfig) error {
	var args []interface{}

	query := `INSERT INTO vpn_configs (session_id, internal_ip, client_public_key, created_at)
              VALUES ($1, $2, $3, $4)
              RETURNING id;`

	args = []interface{}{
		config.SessionID,
		config.InternalIP,
		config.ClientPublicKey,
		config.CreatedAt,
	}
	if err := tx.QueryRow(query, args...).Scan(&config.ID); err != nil {
		return fmt.Errorf("WriteConnectChanges: %v", err)
	}
	return nil
}

func GetFreeIP(tx *sqlx.Tx) (string, error) {
	query := `
        SELECT ip::text
        FROM ip_pool
        WHERE is_used = FALSE
        ORDER BY ip ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED;
    `
	var newIP string
	err := tx.Get(&newIP, query)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("GetFreeIP: Ip pool is full")
		}
		return "", fmt.Errorf("GetFreeIP: %v", err)
	}

	return newIP, nil
}

func GetConfig(tx *sqlx.Tx, publicKey string, sessionID int) (*types.VPNConfig, error) {
	var vpn_config types.VPNConfig
	err := tx.Get(&vpn_config, "SELECT * FROM vpn_configs WHERE session_id = $1", sessionID)

	if err == nil {
		return &vpn_config, nil
	}

	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("GetConfig: %v", err)
	}

	internalIP, err := GetFreeIP(tx)
	if err != nil {
		return nil, fmt.Errorf("GetConfig: %v", err)
	}

	newConfig := types.VPNConfig{
		ID:              0,
		SessionID:       sessionID,
		InternalIP:      internalIP,
		ClientPublicKey: publicKey,
		CreatedAt:       time.Now(),
	}
	return &newConfig, nil
}
func ConnectHandler(wg *wgctrl.Client, config *Config, db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ConnectRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			log.Printf("[ERROR] Invalid request body: %v | Client: %v", err, c.ClientIP())
			return
		}

		sessionID, err := GetIDFromContext(c, "sessionID")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid or expired token"})
			log.Printf("[ERROR] %v", err)
			return
		}

		tx, err := db.Beginx()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			log.Printf("[ERROR] %v", err)
			return
		}
		defer tx.Rollback()

		vpn_config, err := GetConfig(tx, req.PublicKey, sessionID)
		if err != nil {
			log.Printf("[ERROR] %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		if vpn_config.ID == 0 {
			err = WriteConnectChanges(tx, vpn_config)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
				log.Printf("[ERROR] %v", err)
				return
			}
		} else if vpn_config.ClientPublicKey != req.PublicKey {
			log.Printf("[INFO] Key rotation for session %d", sessionID)
			_ = RemoveWireGuardPeer(wg, config, vpn_config.ClientPublicKey)

			err = UpdateClientKey(tx, vpn_config.ID, req.PublicKey)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
				log.Printf("[ERROR] %v", err)
				return
			}
			vpn_config.ClientPublicKey = req.PublicKey
		}

		if err := tx.Commit(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			log.Printf("[ERROR] Commit failed: %v", err)
			return
		}

		err = AddWireGuardPeer(wg, config, vpn_config)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			log.Printf("[ERROR] %v", err)
			return
		}

		device, err := wg.Device(config.Wireguard.Interface)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			log.Printf("[ERROR] Failed to get WG device: %s", err)
			return
		}

		resp := WireguardConfigResponse{
			Interface: InterfaceConfig{
				Address: vpn_config.InternalIP + "/24",
				DNS:     config.Wireguard.DNS,
			},
			Peer: PeerConfig{
				PublicKey: device.PublicKey.String(),
				Endpoint:  fmt.Sprintf("%s:%s", config.API.Domain, config.Wireguard.Port),
				AllowedIPs: []string{
					"0.0.0.0/0",
				},
			},
		}

		c.JSON(http.StatusOK, resp)
		log.Printf("[LOG] Address %v connected successfully", vpn_config.InternalIP)
	}
}
