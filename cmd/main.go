package main

import (
	"log"

	_ "github.com/lib/pq"
	"github.com/nermline/VPN_API_Golang/app"
)

func main() {
	application, err := app.New("config.yaml")
	if err != nil {
		log.Fatalf("[CRITICAL] Failed to initialize app: %v", err)
	}

	defer application.Stop()

	if err := application.Run(); err != nil {
		log.Fatalf("[CRITICAL] Server failed: %v", err)
	}
}
