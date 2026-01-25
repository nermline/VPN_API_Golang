package pkg

import (
	"log"
	"time"

	"github.com/jmoiron/sqlx"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func StartCleanupWorker(wg *wgctrl.Client, config *Config, db *sqlx.DB) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			if err := CleanupStalePeers(wg, config, db); err != nil {
				log.Printf("[ERROR] Cleanup worker failed: %v", err)
			}
		}
	}()
}
