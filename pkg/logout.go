package pkg

import (
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func LogoutHandler(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {

	}
}
