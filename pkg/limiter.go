package pkg

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

func NewRateLimiter(formattedRate string) gin.HandlerFunc {
	rate, err := limiter.NewRateFromFormatted(formattedRate)
	if err != nil {
		log.Fatalf("[CRITICAL] Failed to parse rate limit: %v", err)
	}

	store := memory.NewStore()

	instance := limiter.New(store, rate)

	return mgin.NewMiddleware(instance, mgin.WithLimitReachedHandler(func(c *gin.Context) {
		log.Printf("[WARN] IP %s exceeded rate limit", c.ClientIP())
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": "too many requests",
		})
	}))
}
