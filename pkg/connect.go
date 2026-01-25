package pkg

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
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

func UpdateClientKey(db *sqlx.DB, configID int, newKey string) error {
	_, err := db.Exec("UPDATE vpn_configs SET client_public_key = $1 WHERE id = $2", newKey, configID)
	return fmt.Errorf("UpdateClientKey: ", err)
}

func WriteConnectChanges(db *sqlx.DB, config *types.VPNConfig) error {
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
	if err := db.QueryRow(query, args...).Scan(&config.ID); err != nil {
		return fmt.Errorf("WriteConnectChanges: %v", err)
	}
	return nil
}

func GetFreeIP(db *sqlx.DB, cidr string) (string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("GetFreeIP: %v", err)
	}

	networkIP := ipNet.IP.To4()
	if networkIP == nil {
		return "", errors.New("GetFreeIP: Only IPv4 is supported")
	}

	baseIP := fmt.Sprintf("%d.%d.%d", networkIP[0], networkIP[1], networkIP[2])

	query := fmt.Sprintf(`
        SELECT '%s.' || s.i
        FROM generate_series(2, 254) AS s(i)
        WHERE NOT EXISTS (
            SELECT 1 
            FROM vpn_configs 
            WHERE internal_ip = ('%s.' || s.i)::inet
        )
        ORDER BY s.i ASC
        LIMIT 1;
    `, baseIP, baseIP)

	var newIP string
	err = db.Get(&newIP, query)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("GetFreeIP: IP pool is full")
		}
		return "", fmt.Errorf("GetFreeIP: %v", err)
	}

	return newIP, nil
}

func GetConfig(db *sqlx.DB, publicKey string, sessionID int) (*types.VPNConfig, error) {
	var vpn_config types.VPNConfig
	err := db.Get(&vpn_config, "SELECT * FROM vpn_configs WHERE session_id = $1", sessionID)
	if err != nil {
		if err == sql.ErrNoRows {
			internalIP, err := GetFreeIP(db, "10.0.0.0/24")
			if err != nil {
				return nil, fmt.Errorf("GetConfig: %v", err)
			}
			vpn_config := types.VPNConfig{
				ID:              0,
				SessionID:       sessionID,
				InternalIP:      internalIP,
				ClientPublicKey: publicKey,
				CreatedAt:       time.Now(),
			}
			return &vpn_config, nil
		}
		return nil, fmt.Errorf("GetConfig: %v", err)
	}

	return &vpn_config, nil
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

		var vpn_config *types.VPNConfig
		maxRetries := 3

		for i := 0; i < maxRetries; i++ {
			vpn_config, err = GetConfig(db, req.PublicKey, sessionID)
			if err != nil {
				log.Printf("[ERROR] GetConfig attempt %v failed: %v", i, err)
				if i == maxRetries-1 {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "database busy"})
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}

			if vpn_config.ID != 0 {
				break
			}

			err = WriteConnectChanges(db, vpn_config)
			if err == nil {
				break
			}

			log.Printf("[WARN] Race condition detected for IP %v, retrying...", vpn_config.InternalIP)
			time.Sleep(50 * time.Millisecond)
		}

		if vpn_config.ID != 0 && vpn_config.ClientPublicKey != req.PublicKey {
			log.Printf("[INFO] Key rotation for session %v", sessionID)

			_ = RemoveWireGuardPeer(wg, config, vpn_config.ClientPublicKey)

			err = UpdateClientKey(db, vpn_config.ID, req.PublicKey)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
				log.Printf("[ERROR] %v", err)
				return
			}
			vpn_config.ClientPublicKey = req.PublicKey
		}

		err = AddWireGuardPeer(wg, config, vpn_config)
		if err != nil {
			log.Printf("[ERROR] Failed to add new peer to %v: %v", config.Wireguard.Interface, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		device, err := wg.Device(config.Wireguard.Interface)

		resp := WireguardConfigResponse{
			Interface: InterfaceConfig{
				Address: vpn_config.InternalIP + "/24",
				DNS:     config.Wireguard.DNS,
			},
			Peer: PeerConfig{
				PublicKey:  device.PublicKey.String(),
				Endpoint:   config.API.Domain + config.Wireguard.Port,
				AllowedIPs: []string{"91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22", "91.108.16.0/22", "91.108.12.0/22", "149.154.160.0/20", "91.105.192.0/23", "91.108.20.0/22", "185.76.151.0/24", "10.0.0.0/24"},
			},
		}

		c.JSON(http.StatusOK, resp)
		log.Printf("[LOG] Address %v connected successfully", vpn_config.InternalIP)
	}
}
