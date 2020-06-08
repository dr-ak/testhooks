package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

var handlers []HookHandler

type TempParams struct {
	Port  string
	Hooks []map[string]string
}

func getHookHandler(url string) HookHandler {
	for _, handler := range handlers {
		if handler.getFromUrl() == url {
			return handler
		}
	}
	return nil
}

func MapToStruct(m map[string]string, val interface{}) {
	tmp, err := json.Marshal(m)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	err = json.Unmarshal(tmp, val)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
}

func getHandlers() (out []HookHandler, port string) {
	var params TempParams
	jsonData, err := ioutil.ReadFile("config.json")
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	err = json.Unmarshal(jsonData, &params)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	port = params.Port
	for _, hook := range params.Hooks {
		switch hook["hooktype"] {
		case "http":
			var hookHandler HTTPHookHandler
			MapToStruct(hook, &hookHandler)
			out = append(out, hookHandler)
		case "local":
			var hookHandler LocalHookHandler
			MapToStruct(hook, &hookHandler)
			out = append(out, hookHandler)
		case "ssh":
			var hookHandler SSHHookHandler
			MapToStruct(hook, &hookHandler)
			out = append(out, hookHandler)
		}
	}
	return
}

type HookHandler interface {
	handle(w http.ResponseWriter, r *http.Request, body []byte) bool
	getFromUrl() string
}

func сatchHook(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	secret, _ := os.LookupEnv("SECRET_TOKEN")
	if !IsValidPayload(secret, r.Header.Get("X-Hub-Signature"), body) {
		writeLog("logs/error.log", "Payload did not come from GitHub")
		return
	}
	url := "http://" + r.Host + r.URL.String()
	success := "false"
	hookHandler := getHookHandler(url)
	if hookHandler.handle(w, r, body) {
		success = "true"
	}
	str := "success:[" + success + "] method:[" + r.Method + "] url:[" + url + "] " + fmt.Sprintln(r.Header)
	writeLog("logs/http.log", str[:len(str)-1])
}

func writeLog(fileName string, str string) {
	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	log.SetOutput(f)
	log.Println(str)
}

func writeFile(fileName string, data []byte) {
	file, err := os.Create(fileName)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	defer file.Close()
	file.Write(data)
}

func getEventType() string {
	return ""
}

func main() {
	port := "8080"
	handlers, port = getHandlers()
	r := mux.NewRouter()
	r.HandleFunc("/users/{username}/webhooks/{platform}/{project}/{job}", сatchHook)
	http.Handle("/", r)
	fmt.Println("starting server at " + port)
	http.ListenAndServe(port, nil)
}
