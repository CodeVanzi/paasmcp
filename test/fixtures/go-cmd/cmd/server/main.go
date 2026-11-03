package main

import (
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok go-cmd")) })
	http.ListenAndServe(":"+port, nil)
}
