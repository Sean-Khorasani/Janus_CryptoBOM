package main

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	pool, err := pgxpool.New(context.Background(), "postgres://janus:janus@127.0.0.1:5432/janus?sslmode=disable")
	if err != nil {
		panic(err)
	}
	_, err = pool.Exec(context.Background(), `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
	if err != nil {
		panic(err)
	}
	fmt.Println("Wiped DB schema successfully.")
}
