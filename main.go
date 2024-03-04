package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

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
    rapi.Post("/chirps", postChirps)
    rapi.Get("/chirps", getChirpsGet)
    rapi.Get("/chirps/{chirpID}", getOneChirp)
    r.Mount("/api", rapi)
    r.Mount("/admin", radm)
    corsMux := middlewareCors(r)
    server := &http.Server{
        Addr: ":8080",
        Handler: corsMux,
    }
    log.Fatal(server.ListenAndServe())
    
}

type Chirp struct {
    Id          int     `json:"id"`
    Body string   `json:"body"`
}

func postChirps(w http.ResponseWriter, r *http.Request) {
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
            msg := "Something went wrong"
            respondWithError(w, 500, msg)
            return
    }
    if len(params.Body) >= 140 {
        log.Printf("Message you sent is too long %d chars. Only 140 char is allowed.", len(params.Body)) 
        msg := "Chirp is too long"
        respondWithError(w, 400, msg)
        return
    }
    splitted_msg := strings.Split(params.Body, " ")
    offensive_words := [3]string{
                        "kerfuffle", 
                        "sharbert", 
                        "fornax",
                    }
    cleaned_msg := make([]string, 0)
    for _, val := range splitted_msg {
        word_to_add := val
        for _, word := range offensive_words {
            if strings.ToLower(val) == word {
                word_to_add = "****"
                break
            }

    }
    cleaned_msg = append(cleaned_msg, word_to_add)
    }
    cleaned_msg_joined := strings.Join(cleaned_msg, " ")

    db, err := NewDB("database.json")
    if err != nil {
        log.Print(err) 
    }
    newChirp, err := db.CreateChirp(cleaned_msg_joined)
    if err != nil {
        log.Print(err)
    }
    respondWithJSON(w, 201, newChirp)
    return
}

type DB struct {
    path string
    mux *sync.RWMutex
}

type DBStructure struct {
    Chirps map[int]Chirp `json:"chirps"`
}

func NewDB(path string) (*DB, error) {
    newDB := DB{
        path: path,
        mux: &sync.RWMutex{}, 
    }
    _, err := os.Stat(path)
    if os.IsNotExist(err) {
        f, err := os.Create(path)
        if err != nil {
            log.Print(err)
        }
        defer f.Close()
        return &newDB, nil
    }
    return &newDB, nil
}

func (db *DB) GetChirps() ([]Chirp, error) {
    db.mux.RLock()
    defer db.mux.RUnlock()
    handlingDB := DBStructure{} 
    data, err := os.ReadFile("database.json")
    if err != nil {
        return nil, err
    }
    if err := json.Unmarshal(data, &handlingDB); err != nil {
        return nil, err
    }
    chirpsOut := make([]Chirp, 0)
    for _, val := range handlingDB.Chirps {
        chirpsOut = append(chirpsOut, val)
    }
    sort.Slice(chirpsOut, func(i, j int) bool {return chirpsOut[i].Id < chirpsOut[j].Id})

    return chirpsOut, nil
}

var idCount int = 0

func (db *DB) CreateChirp(body string) (Chirp, error) {
    newChirp := Chirp{}
    db.mux.RLock()
    defer db.mux.RUnlock()
    dbStructure, err := db.loadDB()
    if err != nil {
        log.Print(err)
    }
    idCount++
    newChirp.Id = idCount
    newChirp.Body = body 
    if len(dbStructure.Chirps) == 0 {
        dbStructure.Chirps = make(map[int]Chirp)
    }
    dbStructure.Chirps[int(newChirp.Id)] = newChirp
    err = db.writeDB(dbStructure)

    return newChirp, err

}

func (db *DB) loadDB() (DBStructure, error) {
    db.mux.RLock()
    defer db.mux.RUnlock()
    
    handlingDB := DBStructure{} 
    data, err := os.ReadFile("database.json")
    if err != nil {
        log.Println(err)
    }
    if err := json.Unmarshal(data, &handlingDB); err != nil {
        log.Print(err)
    }
    if len(handlingDB.Chirps) == 0 {
        idCount = 0
    } else {
        idCount = len(handlingDB.Chirps)
    }

    return handlingDB, nil
}
    


func (db *DB) writeDB(dbStructure DBStructure) error {
    db.mux.RLock()
    defer db.mux.RUnlock()
     
    dat, err := json.Marshal(dbStructure)
    if err != nil {
            log.Printf("Error marshalling JSON: %s", err)
            return err
    }

    err = os.WriteFile(db.path, dat, 0666) 


    return err
}


func getChirpsGet(w http.ResponseWriter, r *http.Request) {
    db, err := NewDB("database.json")
    if err != nil {
        log.Print(err) 
    }
    chirps, err := db.GetChirps() 
    if err != nil {
        log.Print(err)
    }
    respondWithJSON(w, 200, chirps)

}

func getOneChirp(w http.ResponseWriter, r *http.Request) {
    db, err := NewDB("database.json")
    param := chi.URLParam(r, "chirpID")

    if err != nil {
        log.Print(err) 
    }
    dbLoaded, err := db.loadDB() 
    if err != nil {
        log.Print(err)
    }
    toInt, err := strconv.Atoi(param)
    if err != nil {
        log.Print(err)
    }
    chirp, ok := dbLoaded.Chirps[toInt]
    if !ok {
        log.Printf("Chirp with id %d not found", toInt)
        msg := "Chirp with id " + param + " not found"
        respondWithError(w, 404, msg)
    } else { 
    respondWithJSON(w, 200, chirp)
    }

}

func respondWithError(w http.ResponseWriter, code int, msg string) {
        type returnError struct {
            Error string `json:"error"`
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(code)
        respBody := &returnError{
            Error: msg,
        }
        dat, err := json.Marshal(respBody)
        if err != nil {
            log.Printf("Error marshalling JSON: %s", err)
            w.WriteHeader(500)
            return
        }
        w.Write(dat)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(code)
        dat, err := json.Marshal(payload)
        if err != nil {
            log.Printf("Error marshalling JSON: %s", err)
            w.WriteHeader(500)
            return
        }
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
