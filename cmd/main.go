package main

import (
	"log"

	"github.com/nermline/VPN_API_Golang/pkg"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

func main() {
	path := "/Users/nermline/Data/Programing projects/VPN_API_Golang/config.yaml"
	cfg, err := pkg.LoadConfig(path)
	if err != nil {
		log.Panic(err)
	}
	log.Println("[LOG] Config " + path + " loaded successfully")

	db, err := pkg.NewPostgres(cfg.Postgres)
	if err != nil {
		log.Panic(err)
	}
	log.Println("[LOG] Postgres database \"" + cfg.Postgres.DBName + "\" connected")
	defer db.Close()

	router := gin.Default()
	router.POST("/v1/auth/register", pkg.RegisterHandler(db))
	router.Run()
}
