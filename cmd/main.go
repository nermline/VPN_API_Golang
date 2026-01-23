package main

import (
	"io"
	"log"
	"os"

	"github.com/nermline/VPN_API_Golang/pkg"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

func main() {
	f, err := os.OpenFile("history.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	multiWriter := io.MultiWriter(f, os.Stdout)
	log.SetOutput(multiWriter)

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

	// gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.POST("/v1/auth/register", pkg.RegisterHandler(db))
	router.POST("/v1/auth/login", pkg.LoginHandler(db))
	router.POST("/v1/auth/refresh", pkg.RefreshHandler(db))
	router.Use(pkg.AuthMiddleware())
	{
		router.GET("/v1/users/me", pkg.UserInfoHandler(db))
		router.POST("/v1/session/connect", pkg.ConnectHandler(db))
		router.POST("/v1/session/disconnect", pkg.DisconnectHandler(db))
		router.POST("/v1/auth/logout", pkg.LogoutHandler(db))

	}
	router.Run("0.0.0.0:8080")
}
