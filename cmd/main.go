package main

import (
	"log"

	"github.com/nermline/VPN_API_Golang/pkg"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

func main() {
	var path = "/Users/nermline/Data/Programing projects/VPN_API_Golang/config.yaml"
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
	router.POST("/api/v1/auth/register", pkg.RegisterUser(db))
	// router.POST("/api/v1/auth/login", pkg.LoginUser(db))
	router.GET("/api/v1/users/availability", pkg.CheckUsernameAvailability(db))
	router.GET("/api/v1/email/availability", pkg.CheckEmailAvailability(db))
	router.Run()
}
