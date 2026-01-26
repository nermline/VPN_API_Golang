package app

import (
	"io"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/nermline/VPN_API_Golang/pkg"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type App struct {
	Cfg     *pkg.Config
	DB      *sqlx.DB
	WG      *wgctrl.Client
	Router  *gin.Engine
	LogFile *os.File
}

func New(configPath string) (*App, error) {
	f, err := os.OpenFile("history.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	multiWriter := io.MultiWriter(f, os.Stdout)
	log.SetOutput(multiWriter)

	cfg, err := pkg.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	log.Println("[LOG] Config loaded successfully")

	db, err := pkg.NewPostgres(cfg.Postgres)
	if err != nil {
		return nil, err
	}
	log.Printf("[LOG] Postgres database \"%s\" connected", cfg.Postgres.DBName)

	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	log.Println("[LOG] Wireguard client connected")

	pkg.StartCleanupWorker(wg, cfg, db)

	if !cfg.API.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	if cfg.API.ForwardedByClientIP {
		router.ForwardedByClientIP = true
		router.SetTrustedProxies([]string{"127.0.0.1"})
	}

	setupRoutes(router, db, wg, cfg)

	return &App{
		Cfg:     cfg,
		DB:      db,
		WG:      wg,
		Router:  router,
		LogFile: f,
	}, nil
}

func (a *App) Run() error {
	address := a.Cfg.API.Listen + ":" + a.Cfg.API.Port
	log.Printf("[LOG] Server starting on %s", address)
	return a.Router.Run(address)
}

func (a *App) Stop() {
	if a.DB != nil {
		a.DB.Close()
	}
	if a.WG != nil {
		a.WG.Close()
	}
	if a.LogFile != nil {
		a.LogFile.Close()
	}
	log.Println("[LOG] Application stopped")
}

func setupRoutes(r *gin.Engine, db *sqlx.DB, wg *wgctrl.Client, cfg *pkg.Config) {
	secretKey := pkg.GetJWTSecret()

	r.POST("/v1/auth/register", pkg.RegisterHandler(db))
	r.POST("/v1/auth/login", pkg.LoginHandler(db, secretKey))
	r.POST("/v1/auth/refresh", pkg.RefreshHandler(db, secretKey))

	authGroup := r.Group("/")
	authGroup.Use(pkg.AuthMiddleware(db, secretKey))
	{
		authGroup.GET("/v1/users/me", pkg.UserInfoHandler(db))
		authGroup.POST("/v1/session/connect", pkg.ConnectHandler(wg, cfg, db))
		authGroup.POST("/v1/session/disconnect", pkg.DisconnectHandler(wg, cfg, db))
		authGroup.POST("/v1/auth/logout", pkg.LogoutHandler(wg, cfg, db))
	}
}
