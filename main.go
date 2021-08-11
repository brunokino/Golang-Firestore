package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"google.golang.org/api/option"
)

type application struct {
	auth struct {
		username string
		password string
	}
}

type LastUpdate struct {
	Atualizado string
	Rede       string
}

type RespJson struct {
	LastUpdate string `json:"lastupdate"`
	NextUpdate string `json:"nextupdate"`
	Now        string `json:"now"`
}

// Inicia comunicação com o Firestore (Firebase) usando credenciais no arquivo "credentials.json" extraído do Firebase Console
func FirebaseInit(ctx context.Context) *firestore.Client {
	opt := option.WithCredentialsFile("credentials.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		fmt.Println("error initializing app or wrong credentials")
	}
	client, err := app.Firestore(ctx)
	if err != nil {
		log.Fatalln(err)
	}
	return client

}

func main() {

	// carrega arquivos .env com as variáveis de ambiente e configurações da aplicação
	// No Git tem o arquivo .env.example como modelo para o .env (que não é recomendado subir para o repositório)
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
		panic("Error loading .env file")
	}

	// Definir credenciais da autenticação básica através do arquivo .env
	app := new(application)
	app.auth.username = os.Getenv("AUTH_USERNAME")
	app.auth.password = os.Getenv("AUTH_PASSWORD")

	// Valida se existe as credenciais no arquivo .env
	if app.auth.username == "" {
		log.Fatal("basic auth username must be provided on .env file")
	}

	if app.auth.password == "" {
		log.Fatal("basic auth password must be provided on .env file")
	}

	// Iniciar servidor Web na porta especificada no arquivo .env
	router := mux.NewRouter()
	router.HandleFunc("/check", app.basicAuth(CheckUpdate)).Methods("POST")
	log.Println("Starting service on port", os.Getenv("PORT"))
	log.Println("#########################################")
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), router))

}

func CheckUpdate(w http.ResponseWriter, r *http.Request) {

	ctx := context.Background()
	client := FirebaseInit(ctx)
	defer client.Close()

	// Set qual Collection e Docuumento queremos ler do banco NoSQL no Firestore
	FirebaseCollection := os.Getenv("COLLECTION")
	FirebaseDoc := os.Getenv("DOC")
	doc, err := client.Collection(FirebaseCollection).Doc(FirebaseDoc).Get(ctx)
	if err != nil {
		log.Fatalln(err)
	}

	// Define layout de data (padrão GoLang) - Estas data e hora passada na variável layout é o padrão do GoLang para escolher o formato da data
	layout := "02/01 15:04"
	timezone, _ := time.LoadLocation("America/Sao_Paulo")
	time.Local = timezone
	now := time.Now().In(timezone)

	j, err := json.Marshal(doc.Data())
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
	}

	// Converte String para Data e set o timezone correto
	resp := LastUpdate{}
	json.Unmarshal([]byte(j), &resp)
	Lastdate, err := time.ParseInLocation(layout, resp.Atualizado, timezone)
	if err != nil {
		fmt.Println(err)
	}

	LastUpdate := Lastdate.AddDate(time.Now().Year(), 0, 0)
	// Soma 45 minutos desde a data e hora da ultima atualização como Target para monitoramento da próxima atualização
	NextDateUpdate := Lastdate.AddDate(time.Now().Year(), 0, 0).Add(time.Minute * 45)

	js := RespJson{
		LastUpdate: LastUpdate.Format(layout),
		NextUpdate: NextDateUpdate.Format(layout),
		Now:        now.Format(layout),
	}

	RespJsonData, err := json.Marshal(js)
	if err != nil {
		fmt.Println(err)
	}

	// Compara se data/hora de próxima atualizar é maior que a data/hora atual e retorna HTTP Status Code para na API
	if NextDateUpdate.After(now) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(RespJsonData))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(RespJsonData))
	}

}

// Autenticação básica e simples
func (app *application) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(app.auth.username))
			expectedPasswordHash := sha256.Sum256([]byte(app.auth.password))

			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
