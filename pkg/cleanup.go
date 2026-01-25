package pkg

import (
	"log"
	"time"

	"github.com/jmoiron/sqlx"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func StartCleanupWorker(wg *wgctrl.Client, db *sqlx.DB) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			if err := CleanupStalePeers(wg, db); err != nil {
				log.Printf("[ERROR] CleanupStalePeers failed: %v", err)
			}
		}
	}()
}
