package pkg

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)

func NewPostgres(cfg DBConfig) (*sqlx.DB, error) {
	destination := fmt.Sprintf(
		"postgres://%s:%s@%s/%s?sslmode=%s",
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.DBName,
		cfg.SSLMode,
	)

	db, err := sqlx.Connect("postgres", destination)
	if err != nil {
		return nil, err
	}

	return db, nil
}


