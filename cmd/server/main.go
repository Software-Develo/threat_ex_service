package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/Software-Develo/threat_ex_service/api"
	"github.com/Software-Develo/threat_ex_service/internal/handler"
	"github.com/Software-Develo/threat_ex_service/internal/storage"
)

func main() {
	dsn := getenv("DATABASE_URL", "postgres://user:passwd@localhost:5432/threats")
	addr := getenv("HTTP_ADDR", ":8080")

	store, err := storage.New(context.Background(), dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	h := handler.New(store)
	router := api.HandlerFromMux(h, http.NewServeMux())

	log.Println("listening on " + addr)
	log.Fatal(http.ListenAndServe(addr, router))
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
