package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

func main() {
    apiCfg := &apiConfig{}
    r := chi.NewRouter()
    rapi := chi.NewRouter()
    radm := chi.NewRouter()
    fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))
    r.Handle("/app/*", fsHandler) 
    r.Handle("/app", fsHandler) 
    rapi.Get("/healthz", healthHandler)
    radm.Get("/metrics", apiCfg.checkFileserverHits)
    rapi.HandleFunc("/reset", apiCfg.resetHits)
    rapi.Post("/validate_chirp", validateChirp)
    r.Mount("/api", rapi)
    r.Mount("/admin", radm)
    corsMux := middlewareCors(r)
    server := &http.Server{
        Addr: ":8080",
        Handler: corsMux,
    }
    log.Fatal(server.ListenAndServe())
    
}

func validateChirp(w http.ResponseWriter, r *http.Request) {
    type parameters struct {
        Body string `json:"body"`
    }
    
    type returnError struct {
        Error string `json:"error"`
    }
    type returnValid struct {
        Valid bool   `json:"valid"`
    }

    decoder := json.NewDecoder(r.Body)
    params := parameters{}
    err := decoder.Decode(&params)
    if err != nil {
        log.Printf("Error decoding paramters %s", err)
        w.WriteHeader(500)
        respBody := &returnError{
            Error: "Something went wrong",
        }
        dat, err := json.Marshal(respBody)
        if err != nil {
            log.Printf("Error marshalling JSON: %s", err)
            w.WriteHeader(500)
            return
        }
        w.Write(dat)
        return
    }
    if len(params.Body) >= 140 {
        log.Printf("Message you sent is too long %d chars. Only 140 char is allowed.", len(params.Body)) 
        w.WriteHeader(400)
        respBody := &returnError{
            Error: "Chirp is too long",
        }
        dat, err := json.Marshal(respBody)
        if err != nil {
            log.Printf("Error marshalling JSON: %s", err)
            w.WriteHeader(500)
            return
        }
        w.Write(dat)
        return
    }
    fmt.Println(params)
 
    respBody := &returnValid{
        Valid: true,
    }

    dat, err := json.Marshal(respBody) 
    if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
        return
	}

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(200)
	w.Write(dat)
    
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(200)
    w.Write([]byte("OK"))
}

func (cfg *apiConfig) checkFileserverHits(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.WriteHeader(200)
    fmt.Fprintf(w, `

<html>

<body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
</body>

</html>


    `, cfg.fileserverHits) 
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
