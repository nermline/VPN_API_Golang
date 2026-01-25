package pkg

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/nermline/VPN_API_Golang/types"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func AddWireGuardPeer(wg *wgctrl.Client, config *Config, vpn_config *types.VPNConfig) error {
	pubKey, err := wgtypes.ParseKey(vpn_config.ClientPublicKey)
	if err != nil {
		return fmt.Errorf("AddWireGuardPeer (%v): %v", vpn_config.ClientPublicKey, err)
	}

	_, ipNet, err := net.ParseCIDR(vpn_config.InternalIP + "/32")
	if err != nil {
		ip := net.ParseIP(vpn_config.InternalIP)
		if ip == nil {
			return fmt.Errorf("AddWireGuardPeer (%v): %v", vpn_config.ClientPublicKey, err)
		}
		ipNet = &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		}
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey:         pubKey,
		Remove:            false,
		UpdateOnly:        false,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{*ipNet},
	}

	err = wg.ConfigureDevice(config.Wireguard.Interface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	})

	if err != nil {
		return fmt.Errorf("AddWireGuardPeer (%v): %v", vpn_config.ClientPublicKey, err)
	}

	return nil
}

func RemoveWireGuardPeer(wg *wgctrl.Client, config *Config, peer string) error {
	pubKey, err := wgtypes.ParseKey(peer)
	if err != nil {
		return fmt.Errorf("RemoveWireGuardPeer (%v): %v", peer, err)
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	err = wg.ConfigureDevice(config.Wireguard.Interface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	})

	if err != nil {
		return fmt.Errorf("RemoveWireGuardPeer (%v): %v", peer, err)
	}

	return nil
}

func CleanupStalePeers(wg *wgctrl.Client, config *Config, db *sqlx.DB) error {
	timeoutDuration := 5 * time.Minute
	cutoffTime := time.Now().Add(-timeoutDuration)

	device, err := wg.Device(config.Wireguard.Interface)
	if err != nil {
		return fmt.Errorf("CleanupStalePeers: Failed to get device: %v", err)
	}

	var peersToRemove []wgtypes.PeerConfig
	var keysToRemove []string

	for _, peer := range device.Peers {
		pubKey := peer.PublicKey.String()
		lastHandshake := peer.LastHandshakeTime
		shouldRemove := false

		if !lastHandshake.IsZero() && time.Since(lastHandshake) > timeoutDuration {
			shouldRemove = true
			log.Printf("[INFO] Peer %v inactive since %v. Marking for removal.", pubKey, lastHandshake)
		}

		if lastHandshake.IsZero() {
			var createdAt time.Time
			err := db.Get(&createdAt, "SELECT created_at FROM vpn_configs WHERE client_public_key = $1", pubKey)

			if err != nil {
				log.Printf("[INFO] Peer %s not found in DB. Removing garbage.", pubKey)
				shouldRemove = true
			} else {
				if createdAt.Before(cutoffTime) {
					shouldRemove = true
					log.Printf("[INFO] Peer %s never connected and expired (created at %s).", pubKey, createdAt)
				}
			}
		}

		if shouldRemove {
			peersToRemove = append(peersToRemove, wgtypes.PeerConfig{
				PublicKey: peer.PublicKey,
				Remove:    true,
			})
			keysToRemove = append(keysToRemove, pubKey)
		}
	}

	if len(peersToRemove) == 0 {
		return nil
	}

	err = wg.ConfigureDevice(config.Wireguard.Interface, wgtypes.Config{
		Peers: peersToRemove,
	})
	if err != nil {
		return fmt.Errorf("Failed to remove peers from %v: %v", config.Wireguard.Interface, err)
	}

	queryDeleteConfigs := `DELETE FROM vpn_configs WHERE client_public_key IN (?)`
	queryDeleteConfigs, argsConfig, err := sqlx.In(queryDeleteConfigs, keysToRemove)
	if err != nil {
		return fmt.Errorf("Failed to remove peers from %v: %v", config.Wireguard.Interface, err)
	}
	queryDeleteConfigs = db.Rebind(queryDeleteConfigs)

	result, err := db.Exec(queryDeleteConfigs, argsConfig...)
	if err != nil {
		return fmt.Errorf("Failed to remove peers from %v: %v", config.Wireguard.Interface, err)
	}

	rows, _ := result.RowsAffected()
	log.Printf("[INFO] Cleaned up %d inactive peers.", rows)

	return nil
}
