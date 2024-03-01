package main

import (
    "net/http"
    "log"
    "strconv"
    "github.com/go-chi/chi/v5"
)

func main() {
    apiCfg := &apiConfig{}
    r := chi.NewRouter()
    //mux := http.NewServeMux()
    fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir("."))))
    r.Handle("/app/", fsHandler) 
    r.Handle("/app/*", fsHandler) 
    r.Handle("/app", fsHandler) 
    r.HandleFunc("/healthz", healthHandler)
    r.HandleFunc("/metrics", apiCfg.checkFileserverHits)
    r.HandleFunc("/reset", apiCfg.resetHits)
    corsMux := middlewareCors(r)
    server := &http.Server{
        Addr: ":8080",
        Handler: corsMux,
    }
    log.Fatal(server.ListenAndServe())
    
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(200)
    w.Write([]byte("OK"))
}

func (cfg *apiConfig) checkFileserverHits(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(200)
    w.Write([]byte("Hits: " + strconv.Itoa(cfg.fileserverHits))) 
}

func (cfg *apiConfig) resetHits(w http.ResponseWriter, r *http.Request) {
    cfg.fileserverHits = 0
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(200)
    w.Write([]byte("Hits reseted back to: " + strconv.Itoa(cfg.fileserverHits))) 
}
    

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
    return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
        cfg.fileserverHits++
        next.ServeHTTP(w, r)
    })
}

type apiConfig struct {
	fileserverHits int
}
