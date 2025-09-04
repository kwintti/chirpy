package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/kwintti/chirpy/internal/database"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
)

func main() {
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Print(err)
	}
	dbQueries := database.New(db)
    dbg := flag.Bool("debug", false, "Enable debug mode")
    flag.Parse()
    if *dbg {
        err := os.Remove("database.json")
        if err != nil {
            log.Print(err)
        }
    }
    apiCfg := &apiConfig{}
	apiCfg.dbQueries = dbQueries

    ServeMux := http.NewServeMux()
	ServeMux.Handle("/", http.FileServer(http.Dir(".")))
	ServeMux.Handle("GET /app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	ServeMux.HandleFunc("GET /metrics", apiCfg.checkFileserverHits)
	ServeMux.HandleFunc("POST /reset", apiCfg.resetHits)

    server := &http.Server{
        Addr: ":8080",
        Handler: ServeMux,
    }
    log.Fatal(server.ListenAndServe())
    
}


type Chirp struct {
    Id          int     `json:"id"`
    Body        string  `json:"body"`
    AuthorId    int     `json:"author_id"`
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
    godotenv.Load()
    jwtSecret := os.Getenv("JWT_SECRET") 
    myClaims := myClaims{}
    token_with_bear := r.Header.Get("Authorization")
    tokenString := strings.TrimPrefix(token_with_bear, "Bearer ")
    _, err := jwt.ParseWithClaims(tokenString, &myClaims, func(token *jwt.Token) (any, error) {
        return []byte(jwtSecret), nil
    })
    if err != nil {
        respondWithError(w, 401, "invalid token")
        log.Print(err)
        return
    }
    authorId := myClaims.Subject
    decoder := json.NewDecoder(r.Body)
    params := parameters{}
    err = decoder.Decode(&params)
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
    idInt, err := strconv.Atoi(authorId)
    if err != nil {
        log.Print(err)
    }
    
    newChirp, err := db.CreateChirp(cleaned_msg_joined, idInt)
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
    Users map[int]User `json:"users"`
    Tokens map[int]Token `json:"revoked_tokens"`
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

func (db *DB) GetChirps(authorID, sortIt string) ([]Chirp, error) {
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
    if len(authorID) != 0 {
        authorIDInt, err := strconv.Atoi(authorID)
        for _, val := range handlingDB.Chirps {
            if val.AuthorId == authorIDInt {
                chirpsOut = append(chirpsOut, val)
            }
        if err != nil {
            return nil, err
        }
      }
    } else {
    for _, val := range handlingDB.Chirps {
        chirpsOut = append(chirpsOut, val)
    }
}
    if sortIt == "asc" {
        sort.Slice(chirpsOut, func(i, j int) bool {return chirpsOut[i].Id < chirpsOut[j].Id})
    } else {
        sort.Slice(chirpsOut, func(i, j int) bool {return chirpsOut[i].Id > chirpsOut[j].Id})
    }


    return chirpsOut, nil
}


func (db *DB) CreateChirp(body string, authorId int) (Chirp, error) {
    newChirp := Chirp{}
    db.mux.RLock()
    defer db.mux.RUnlock()
    dbStructure, err := db.loadDB()
    if err != nil {
        log.Print(err)
    }
    idCountChirps++
    newChirp.Id = idCountChirps
    newChirp.Body = body 
    newChirp.AuthorId = authorId
    if len(dbStructure.Chirps) == 0 {
        dbStructure.Chirps = make(map[int]Chirp)
    }
    dbStructure.Chirps[int(newChirp.Id)] = newChirp
    err = db.writeDB(dbStructure)

    return newChirp, err

}
var idCount int  
var idCountChirps int
var idCountTokens int

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
        idCountChirps = 0
    } else {
        keys := make([]int, 0, len(handlingDB.Chirps))
        for k := range handlingDB.Chirps {
            keys = append(keys, k)
        }
        sort.Ints(keys)
        idCountChirps = keys[len(keys)-1]
    }
    if len(handlingDB.Users) == 0 {
        idCount = 0
    } else {
        keys := make([]int, 0, len(handlingDB.Users))
        for k := range handlingDB.Users {
            keys = append(keys, k)
        }
        sort.Ints(keys)
        idCount = keys[len(keys)-1]
    }
    if len(handlingDB.Tokens) == 0 {
        idCountTokens = 0
    } else {
        keys := make([]int, 0, len(handlingDB.Tokens))
        for k := range handlingDB.Tokens {
            keys = append(keys, k)
        }
        sort.Ints(keys)
        idCountTokens = keys[len(keys)-1]
    }

    return handlingDB, nil
}

type Polka struct {
    Event   string  `json:"event"`
    Data    data  `json:"data"`
}

type data struct {
    UserId   int    `json:"user_id"`
}
    
func checkIfChirpyRed(w http.ResponseWriter, r *http.Request) {
    godotenv.Load()
    jwtPolka := os.Getenv("POLKA_SECRET") 
    db, err := NewDB("database.json")
    params := Polka{}
    tokenUnParsed := r.Header.Get("Authorization")
    token := strings.TrimPrefix(tokenUnParsed, "ApiKey ")
    if token != jwtPolka {
        respondWithError(w, 401, "invalid token")
        return
    }
    decoder := json.NewDecoder(r.Body)
    err = decoder.Decode(&params)
    if err != nil {
        respondWithError(w, 403, "Couldn't decode json")
        return
    }
    if params.Event != "user.upgraded" {
        w.WriteHeader(200)
        return
    }
    err = db.addChirpyRed(params.Data.UserId)
    if err != nil {
        w.WriteHeader(404)
    }

}

func (db *DB) addChirpyRed(id int) error {
    db.mux.RLock()
    defer db.mux.RUnlock()

    return nil 
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
    var chirps []Chirp 
    authorId := r.URL.Query().Get("author_id")
    sort := r.URL.Query().Get("sort")
    if len(sort) == 0 {
        sort = "asc"
    }
    if len(authorId) != 0 {
        chirps, err = db.GetChirps(authorId, sort) 
        if err != nil {
            log.Print(err)
        }
    } else {    
        chirps, err = db.GetChirps("", sort) 
        if err != nil {
            log.Print(err)
        }
    }
    respondWithJSON(w, 200, chirps)

}

func getOneChirp(w http.ResponseWriter, r *http.Request) {

    respondWithJSON(w, 200, Chirp{})
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

type User struct {
    Id      uuid.UUID     `json:"id"`
    Email   string  `json:"email"`
}

type Token struct {
    Revoked time.Time   `json:"revoked"`
    Token   string `json:"token"`
}

func (u User) PasswordOmited() map[string]interface{} {
    return map[string]interface{}{
        "id":       u.Id,
        "email":    u.Email,
    }
}

func (u User) ShowToken() map[string]interface{} {
    return map[string]interface{}{
        "id":       u.Id,
        "email":    u.Email,
    }
}

func (u User) OnlyToken() map[string]interface{} {
    return map[string]interface{}{
    }
}

func (u User) MaskLogin() map[string]interface{} {
    return map[string]interface{}{
        "id":       u.Id,
        "email":    u.Email,
    }
}

func (db *DB) addNewUser(email, password string) (User, error) {
    newUser := User{}
    db.mux.RLock()
    defer db.mux.RUnlock()
    dbStructure, err := db.loadDB()
    if err != nil {
        log.Print(err)
    }
    idCount++
    newUser.Email = email 
    emailDuplicateFound := false
    for _, val := range dbStructure.Users {
        if val.Email == email {
            emailDuplicateFound = true
        }
    }

    if !emailDuplicateFound {

    if len(dbStructure.Users) == 0 {
        dbStructure.Users = make(map[int]User)
    }
    err = db.writeDB(dbStructure)
    return newUser, err
}
    err = errors.New("Email already in use. User not created") 

    return User{}, err
    
}

func (db *DB) updateUser(email, password string, id int) (User, error) {
    db.mux.RLock()
    defer db.mux.RUnlock()
    loadedUser := User{
                    Email: email,
                    }
    return loadedUser, nil 
}

type parameters struct {
    Email string `json:"email"`
    Password string `json:"password"`
    Expires int     `json:"expires_in_seconds,omitempty"`
}

func addUserPost(w http.ResponseWriter, r *http.Request) {
    usr, err := NewDB("database.json")
    if err != nil {
        log.Print(err)
    }
    decoder := json.NewDecoder(r.Body)
    params := parameters{}
    err = decoder.Decode(&params)
    if err != nil {
            log.Printf("Error decoding paramters %s", err)
            msg := "Something went wrong"
            respondWithError(w, 500, msg)
            return
    }
    newUser, err := usr.addNewUser(params.Email, params.Password)
    if err != nil {
        log.Print(err)
        respondWithError(w, 403, "User with same email already exists")
    } else {
        newUserPasswordless := newUser.PasswordOmited()
        respondWithJSON(w, 201, newUserPasswordless)
    }
    
}

func userLoginPost(w http.ResponseWriter, r *http.Request) {
    usr, err := NewDB("database.json")
    if err != nil {
        log.Print(err)
    }
    decoder := json.NewDecoder(r.Body)
    params := parameters{}
    err = decoder.Decode(&params)
    if err != nil {
            log.Printf("Error decoding paramters %s", err)
            msg := "Something went wrong"
            respondWithError(w, 500, msg)
            return
    }
    logingUser, err :=  usr.userLogin(params.Email, params.Password) 
    if err != nil {
        log.Print(err)
        respondWithError(w, 401, "Wrong password")
    } else {
        loginUserPasswordless := logingUser.PasswordOmited()
        respondWithJSON(w, 200, loginUserPasswordless)
    }
    

}

func (db *DB) userLogin(email, password string) (User, error){
    loginUser := User{}
    db.mux.RLock()
    defer db.mux.RUnlock()
    dbStructure, err := db.loadDB()
    if err != nil {
        log.Print(err)
    }
    for _, val := range dbStructure.Users {
        if email == val.Email {
            loginUser = val
            err = db.writeDB(dbStructure)
            return loginUser, err
        }
    }
    err = errors.New("User not found")
    return loginUser, err 
}

func userRefreshPost(w http.ResponseWriter, r *http.Request) {
    db, err := NewDB("database.json")
    if err != nil {
        log.Print(err)
    }
    revokedTokens, err := db.loadDB()
    godotenv.Load()
    jwtSecret := os.Getenv("JWT_SECRET") 
    myClaims := myClaims{}
    token_with_bear := r.Header.Get("Authorization")
    tokenString := strings.TrimPrefix(token_with_bear, "Bearer ")
    _, err = jwt.ParseWithClaims(tokenString, &myClaims, func(token *jwt.Token) (interface{}, error) {
        return []byte(jwtSecret), nil
    })
    if err != nil {
        respondWithError(w, 401, "invalid token")
        log.Print(err)
        return
    }
    if myClaims.Issuer != "chirpy-refresh" {
        respondWithError(w, 401, "This token is not Refresh token.")
        return
    }
    for _, val := range revokedTokens.Tokens {
        if val.Token == tokenString {
            respondWithError(w, 401, "This token is revoked")
            return
        }
    }
    
    
}

func revokeToken(w http.ResponseWriter, r *http.Request) {
    db, err := NewDB("database.json")
    if err != nil {
        log.Print(err)
    }
    idCountTokens++
    revokedTokens, err := db.loadDB()
    token_with_bear := r.Header.Get("Authorization")
    tokenString := strings.TrimPrefix(token_with_bear, "Bearer ")
    tokenToWrite := Token{
                        Revoked: time.Now(),
                        Token: tokenString,}

     
    if len(revokedTokens.Tokens) == 0 {
        revokedTokens.Tokens = make(map[int]Token)
    }
    revokedTokens.Tokens[idCountTokens] = tokenToWrite

    err = db.writeDB(revokedTokens)
}

func deleteChirpDELETE(w http.ResponseWriter, r *http.Request) {
    // db, err := NewDB("database.json")
    // if err != nil {
    //     log.Print(err)
    // }
    // deleteChirp, err := db.loadDB()
    // token_with_bear := r.Header.Get("Authorization")
    // tokenString := strings.TrimPrefix(token_with_bear, "Bearer ")
    // godotenv.Load()
    // jwtSecret := os.Getenv("JWT_SECRET") 
    // userClaims := myClaims{}
    // _, err = jwt.ParseWithClaims(tokenString, &userClaims, func(t *jwt.Token) (interface{}, error) {
    //         return []byte(jwtSecret), nil 
    //     })
    // if err != nil {
    //     respondWithError(w, 401, "invalid token")
    //     log.Print(err)
    //     return
    // }
    //
    // idInt, err := strconv.Atoi(userClaims.Subject)
    // chirpIdInt, err := strconv.Atoi(chirpId)
    // for _, val := range deleteChirp.Chirps {
    //     if val.Id == chirpIdInt {
    //         if val.AuthorId == idInt{
    //             delete(deleteChirp.Chirps, val.Id)
    //             err = db.writeDB(deleteChirp)
    //             return
    //         }
    //     }
    // }
    // respondWithError(w, 403, "Something went wrong")
} 
    


func generateHashForPassword(password string) ([]byte, error) {
    cost := 10
    hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
    if err != nil {
        return nil, err
    }
    return hash, err
}

type myClaims struct {
    Issuer string
    Subject string
    jwt.RegisteredClaims
}

func createToken(user_id string) (string, error) {
    godotenv.Load()
    jwtSecret := os.Getenv("JWT_SECRET")
    expires_in_seconds := 3600
    claims := myClaims{
            RegisteredClaims: jwt.RegisteredClaims{
                ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expires_in_seconds) * time.Second)),
            },
            Issuer: "chirpy-access",
            Subject: user_id,
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    token_signed, err := token.SignedString([]byte(jwtSecret))
    if err != nil {
        return "", err
    }

    return token_signed, nil
}

func createRefreshToken(user_id string) (string, error) {
    godotenv.Load()
    jwtSecret := os.Getenv("JWT_SECRET")
    expires_in_hours := 1440
    claims := myClaims{
            RegisteredClaims: jwt.RegisteredClaims{
                ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expires_in_hours) * time.Hour)),
            },
            Issuer: "chirpy-refresh",
            Subject: user_id,
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    token_signed, err := token.SignedString([]byte(jwtSecret))
    if err != nil {
        return "", err
    }

    return token_signed, nil
}

func updateUserPut(w http.ResponseWriter, r *http.Request) {
    updUsr, err := NewDB("database.json")
    if err != nil {
        log.Print(err)
    }

    godotenv.Load()
    jwtSecret := os.Getenv("JWT_SECRET") 
    myClaims := myClaims{}
    token_with_bear := r.Header.Get("Authorization")
    tokenString := strings.TrimPrefix(token_with_bear, "Bearer ")
    _, err = jwt.ParseWithClaims(tokenString, &myClaims, func(token *jwt.Token) (interface{}, error) {
        return []byte(jwtSecret), nil
    })
    if err != nil {
        respondWithError(w, 401, "invalid token")
        log.Print(err)
        return
    }
    if myClaims.Issuer == "chirpy-refresh" {
        log.Print("Refresh token is used, Access token is needed.")
        respondWithError(w, 401, "Refresh token is used. Access token is required.")
        return
    }
    id := myClaims.Subject 
    decoder := json.NewDecoder(r.Body)
    params := parameters{}
    err = decoder.Decode(&params)
    if err != nil {
        log.Print(err)
    }
    idInt, err := strconv.Atoi(id)
    if err != nil {
        log.Print(err)
    }
    updatedUser, err := updUsr.updateUser(params.Email, params.Password, idInt) 
    updateUserPasswordless := updatedUser.PasswordOmited()

    respondWithJSON(w, 200, updateUserPasswordless)
    
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


    `, cfg.fileserverHits.Load()) 
}

func (cfg *apiConfig) resetHits(w http.ResponseWriter, r *http.Request) {
    cfg.fileserverHits.Store(0)
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(200)
    w.Write([]byte("Hits reseted back to: " + strconv.Itoa(int(cfg.fileserverHits.Load())))) 
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
        cfg.fileserverHits.Add(1)
        next.ServeHTTP(w, r)
    })
}

type apiConfig struct {
	fileserverHits atomic.Int32 
	dbQueries *database.Queries
}
