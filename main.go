package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

var port = ""
var path = ""
var cisUrl = ""

func initParams() {
	params, err := readParams("hook.conf")
	fmt.Println(params)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	port = params["port"]
	path = params["path"]
	cisUrl = params["cis_url"]
}

func readParams(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	lines := make(map[string]string, 0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		params := strings.Split(scanner.Text(), "=")
		lines[params[0]] = params[1]
	}
	return lines, scanner.Err()
}

func сatchHook(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{}
	req, _ := http.NewRequest(r.Method, cisUrl, r.Body)
	req.Header = r.Header
	req.PostForm = r.PostForm
	resp, _ := client.Do(req)
	success := "false"
	if resp.StatusCode == 200 {
		success = "true"
	}
	str := "success:[" + success + "] method:[" + r.Method + "] url:[" + r.URL.String() + "] " + fmt.Sprintln(r.Header)
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

func main() {
	initParams()
	http.HandleFunc(path, сatchHook)
	fmt.Println("starting server at :" + port)
	http.ListenAndServe(port, nil)
}
