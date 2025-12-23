package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

var DBUser = "vpnuser"
var DBPassword = "1423"
var DBNetwork = "localhost"
var DBName = "vpnservice"

var PostgresLink = "postgres://" + DBUser + ":" + DBPassword + "@" + DBNetwork + "/" + DBName + "?sslmode=disable"

func main() {
	db, err := sqlx.Connect("postgres", PostgresLink)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	fmt.Println("Connected to PostgreSQL!")

	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) { c.JSON(200, gin.H{"message": "pong"}) })
	router.Run()
}
