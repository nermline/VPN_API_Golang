package pkg

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/nermline/VPN_API_Golang/classes"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const WGInterface = "wg0"

func AddWireGuardPeer(wg *wgctrl.Client, config *classes.VPNConfig) error {
	pubKey, err := wgtypes.ParseKey(config.ClientPublicKey)
	if err != nil {
		return err
	}

	_, ipNet, err := net.ParseCIDR(config.InternalIP + "/32")
	if err != nil {
		ip := net.ParseIP(config.InternalIP)
		if ip == nil {
			return err
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

	err = wg.ConfigureDevice(WGInterface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	})

	if err != nil {
		return err
	}

	return nil
}

func RemoveWireGuardPeer(wg *wgctrl.Client, peer string) error {
	pubKey, err := wgtypes.ParseKey(peer)
	if err != nil {
		return fmt.Errorf("invalid public key in db: %w", err)
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	err = wg.ConfigureDevice(WGInterface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	})

	if err != nil {
		return err
	}

	return nil
}

func CleanupStalePeers(wg *wgctrl.Client, db *sqlx.DB) error {
	timeoutDuration := 5 * time.Minute
	cutoffTime := time.Now().Add(-timeoutDuration)

	device, err := wg.Device(WGInterface)
	if err != nil {
		return fmt.Errorf("failed to get device: %w", err)
	}

	var peersToRemove []wgtypes.PeerConfig
	var keysToRemove []string

	for _, peer := range device.Peers {
		pubKey := peer.PublicKey.String()
		lastHandshake := peer.LastHandshakeTime
		shouldRemove := false

		// ВАРІАНТ А: Користувач підключався, але давно (> 5 хв)
		if !lastHandshake.IsZero() && time.Since(lastHandshake) > timeoutDuration {
			shouldRemove = true
			log.Printf("[INFO] Peer %s inactive since %s. Marking for removal.", pubKey, lastHandshake)
		}

		// ВАРІАНТ Б: Користувач НІКОЛИ не підключався (Handshake == 0)
		// Треба перевірити, чи це не свіжий акаунт, створений 1 хвилину тому.
		if lastHandshake.IsZero() {
			var createdAt time.Time
			// Перевіряємо дату створення в БД
			err := db.Get(&createdAt, "SELECT created_at FROM vpn_configs WHERE client_public_key = $1", pubKey)

			if err != nil {
				// Якщо запису немає в БД, але він висить у WG — це сміття, видаляємо
				log.Printf("[WARN] Peer %s not found in DB. Removing garbage.", pubKey)
				shouldRemove = true
			} else {
				// Якщо запис є, перевіряємо, чи він "старий"
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

	// 3. Якщо нікого видаляти — виходимо
	if len(peersToRemove) == 0 {
		log.Printf("[CLEAN] Nothing to clean")
		return nil
	}

	// 4. Видаляємо з інтерфейсу WireGuard (пакетом)
	err = wg.ConfigureDevice(WGInterface, wgtypes.Config{
		Peers: peersToRemove,
	})
	if err != nil {
		return fmt.Errorf("failed to remove peers from interface: %w", err)
	}

	// 5. Видаляємо/Оновлюємо записи в БД
	// Використовуємо sqlx.In для масового запиту

	// Крок 5.2: Видаляємо самі конфіги (як ви просили "видаляти записи")
	queryDeleteConfigs := `DELETE FROM vpn_configs WHERE client_public_key IN (?)`
	queryDeleteConfigs, argsConfig, err := sqlx.In(queryDeleteConfigs, keysToRemove)
	if err != nil {
		return err
	}
	queryDeleteConfigs = db.Rebind(queryDeleteConfigs)

	result, err := db.Exec(queryDeleteConfigs, argsConfig...)
	if err != nil {
		return fmt.Errorf("failed to delete configs from DB: %w", err)
	}

	rows, _ := result.RowsAffected()
	log.Printf("[SUCCESS] Cleaned up %d inactive peers.", rows)

	return nil
}
