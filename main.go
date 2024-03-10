package main

import (
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
	"time"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

func main() {
    dbg := flag.Bool("debug", false, "Enable debug mode")
    flag.Parse()
    if *dbg {
        err := os.Remove("database.json")
        if err != nil {
            log.Print(err)
        }
    }
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
    rapi.Post("/users", addUserPost)
    rapi.Post("/revoke", revokeToken)
    rapi.Post("/login", userLoginPost)
    rapi.Post("/refresh", userRefreshPost)
    rapi.Put("/users", updateUserPut)
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
    if len(handlingDB.Users) == 0 {
        idCount = 0
    } else {
        idCount = len(handlingDB.Users)
    }
    if len(handlingDB.Tokens) == 0 {
        idCount = 0
    } else {
        idCount = len(handlingDB.Tokens)
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

type User struct {
    Id      int     `json:"id"`
    Email   string  `json:"email"`
    Password string `json:"password"`
    Token   string  `json:"token"`
    RefreshToken string `json:"refresh_token"`
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
        "token":    u.Token,
        "refresh_token": u.RefreshToken,
    }
}

func (u User) OnlyToken() map[string]interface{} {
    return map[string]interface{}{
        "token":    u.Token,
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
    hash, err := generateHashForPassword(password)
    if err != nil {
        log.Print(err)
    } 
    newUser.Id = idCount
    newUser.Email = email 
    newUser.Password = string(hash)
    newUser.Token, err = createToken(strconv.Itoa(idCount))
    if err != nil {
        return User{}, err
    }
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
    dbStructure.Users[int(newUser.Id)] = newUser
    err = db.writeDB(dbStructure)
    return newUser, err
}
    err = errors.New("Email already in use. User not created") 

    return User{}, err
    
}

func (db *DB) updateUser(email, password string, id int) (User, error) {
    db.mux.RLock()
    defer db.mux.RUnlock()
    hash, err := generateHashForPassword(password)
    if err != nil {
        log.Print(err)
    } 
    loadedUser := User{
                    Id: id,
                    Email: email,
                    Password: string(hash),
                    }
    dbStructure, err := db.loadDB()
    if err != nil {
        return User{}, err
    }
    for _, val := range dbStructure.Users {
        if val.Id == id {
            loadedUser.Token = dbStructure.Users[id].Token
            loadedUser.RefreshToken = val.RefreshToken
            dbStructure.Users[id] = loadedUser
            err = db.writeDB(dbStructure)
            return loadedUser, err
        }
    }
    err = errors.New("user not found")
    return loadedUser, err
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
        loginUserPasswordless := logingUser.ShowToken()
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
            loginUser.Email = val.Email
            loginUser.Id = val.Id
            loginUser.Password = val.Password
            loginUser.Token, err = createToken(strconv.Itoa(val.Id))
            loginUser.RefreshToken, err = createRefreshToken(strconv.Itoa(val.Id))
            err := bcrypt.CompareHashAndPassword([]byte(val.Password), []byte(password))
            if err != nil {
                return User{}, err
            }
            dbStructure.Users[val.Id] = loginUser
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
    user := User{}
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
    for _, val := range revokedTokens.Users {
        if tokenString == val.RefreshToken {
            user.Token, err = createToken(strconv.Itoa(val.Id))
            user.Email = val.Email
            user.Id = val.Id
            user.Password = val.Password
            user.RefreshToken = val.RefreshToken
            if err != nil {
                log.Print("Couldn't create token")
                return
            }
            revokedTokens.Users[val.Id] = user
            err = db.writeDB(revokedTokens)
            respondWithJSON(w, 200, user.OnlyToken())    
            return
        }
    }
    
    
}

func revokeToken(w http.ResponseWriter, r *http.Request) {
    db, err := NewDB("database.json")
    if err != nil {
        log.Print(err)
    }
    idCount++
    revokedTokens, err := db.loadDB()
    token_with_bear := r.Header.Get("Authorization")
    tokenString := strings.TrimPrefix(token_with_bear, "Bearer ")
    tokenToWrite := Token{
                        Revoked: time.Now(),
                        Token: tokenString,}

     
    if len(revokedTokens.Tokens) == 0 {
        revokedTokens.Tokens = make(map[int]Token)
    }
    revokedTokens.Tokens[idCount] = tokenToWrite
    err = db.writeDB(revokedTokens)
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
