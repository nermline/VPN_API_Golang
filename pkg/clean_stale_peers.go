package pkg

import (
	"log"
	"time"

	"github.com/jmoiron/sqlx"
)

func CleanupStalePeers(db *sqlx.DB) error {
	return nil
}

func StartCleanupWorker(db *sqlx.DB) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			if err := CleanupStalePeers(db); err != nil {
				log.Printf("[ERROR] CleanupStalePeers failed: %v", err)
			}
		}
	}()
}
