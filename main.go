package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/gorilla/mux"
	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var params Params

type Params struct {
	Port  string
	Hooks []hook
}

type hook struct {
	FromUrl         string
	HookType        string
	ToUrl           string
	Address         string
	Port            string
	User            string
	BaseDir         string
	Job             string
	Requestbodypath string
}

func (h hook) getFromUrl() string {
	return h.FromUrl
}

func (h hook) getType() string {
	return h.HookType
}

func (h hook) getToUrl() string {
	return h.ToUrl
}

func (h hook) getAddress() string {
	return h.Address
}

func (h hook) getPort() string {
	return h.Port
}

func (h hook) getUser() string {
	return h.User
}

func (h hook) getBaseDir() string {
	return h.BaseDir
}

func (h hook) getJob() string {
	return h.Job
}

func (h hook) getRequestBodyPath() string {
	return h.Requestbodypath
}

func (p Params) getHook(url string) (out *hook) {
	out = nil
	for _, hook := range p.Hooks {
		if hook.getFromUrl() == url {
			return &hook
		}
	}
	return out
}

func moveFileOnSsh(h *hook, from, to string) {
	session, err := getSshSession(h)
	defer session.Close()
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	fmt.Println(from, to)
	err = scp.CopyPath(from, to, session)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	err = os.Remove(from)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
}

func getClientConfig(h *hook) *ssh.ClientConfig {
	user, err := user.Current()
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	key, err := ioutil.ReadFile(user.HomeDir + "/.ssh/id_rsa")
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	hostKeyCallback, err := knownhosts.New(user.HomeDir + "/.ssh/known_hosts")
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	return &ssh.ClientConfig{
		User: h.getUser(),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
	}
}

func getSshSession(h *hook) (*ssh.Session, error) {
	client, err := ssh.Dial("tcp", h.getAddress()+":"+h.getPort(), getClientConfig(h))
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	session, err := client.NewSession()
	return session, err
}

func сatchHook(w http.ResponseWriter, r *http.Request) {
	url := "http://" + r.Host + r.URL.String()
	success := "false"
	hook := params.getHook(url)
	if hook != nil {
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
		switch hook.getType() {
		case "http":
			respBody := bytes.NewReader(body)
			client := &http.Client{}
			req, err := http.NewRequest(r.Method, hook.getToUrl(), respBody)
			if err != nil {
				writeLog("logs/error.log", err.Error())
			}
			req.Header = r.Header
			req.PostForm = r.PostForm
			resp, err := client.Do(req)
			if err != nil {
				writeLog("logs/error.log", err.Error())
			}
			if resp.StatusCode == http.StatusOK {
				success = "true"
			}
			w.WriteHeader(resp.StatusCode)
		case "ssh":
			pwd, err := os.Getwd()
			if err != nil {
				writeLog("logs/error.log", err.Error())
			}
			from := pwd + "/request_body.json"
			to := hook.getBaseDir() + hook.getRequestBodyPath()
			writeFile(from, body)
			moveFileOnSsh(hook, from, to)
			status := RunSsh(hook)
			if status == http.StatusOK {
				success = "true"
			}
			w.WriteHeader(status)
		case "local":
			writeFile(os.Getenv("cis_base_dir")+"/"+hook.getRequestBodyPath(), body)
			status := RunLocal(hook)
			if status == http.StatusOK {
				success = "true"
			}
			w.WriteHeader(status)
		}
	}
	str := "success:[" + success + "] method:[" + r.Method + "] url:[" + url + "] " + fmt.Sprintln(r.Header)
	writeLog("logs/http.log", str[:len(str)-1])
}

func RunLocal(h *hook) int {
	envVars := make([]string, 0)
	envVars = append(envVars, readEnvVarsFromCis(h)...)
	envVars = append(envVars, getEnvVars(h)...)
	command := h.getBaseDir() + "/core/" + getStartJob(envVars)
	cmd := exec.Command(command, h.getJob())
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Env = append(os.Environ(), envVars...)
	err := cmd.Run()
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	out := buf.String()[0 : len(buf.String())-1]
	fmt.Println(out)
	if strings.Index(out, "Exit code: 0") != -1 {
		return http.StatusOK
	}
	return http.StatusBadRequest
}

func getStartJob(envVars []string) string {
	for _, envVar := range envVars {
		if strings.HasPrefix(envVar, "startjob") {
			return envVar[strings.Index(envVar, "=")+1:]
		}
	}
	return ""
}

func getOutOfSshCommand(h *hook, command string, envVars ...string) string {
	session, err := getSshSession(h)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	defer session.Close()
	for _, envVar := range envVars {
		envAsArr := strings.Split(envVar, "=")
		err := session.Setenv(envAsArr[0], envAsArr[1])
		if err != nil {
			fmt.Println(err.Error())
		}
	}
	b, err := session.CombinedOutput(command)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	out := string(b)
	if out[len(out)-1:] == "\n" {
		return out[:len(out)-1]
	} else {
		return out
	}
}

func readEnvVarsFromCisOnSsh(h *hook) []string {
	result := make([]string, 0)
	cisEnv := strings.Split(getOutOfSshCommand(h, "cat "+h.getBaseDir()+"/core/cis.conf"), "\n")
	result = append(result, cisEnv...)
	project := h.getJob()[:strings.Index(h.getJob(), "/")]
	jobEnv := strings.Split(getOutOfSshCommand(h, "cat "+h.getBaseDir()+"/jobs/"+project+"/job.conf"), "\n")
	result = append(result, jobEnv...)
	return result
}

func readEnvVarsFromCis(h *hook) []string {
	result := make([]string, 0)
	cisEnv, err := readConfFile("/core/cis.conf")
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	result = append(result, cisEnv...)
	project := h.getJob()[:strings.Index(h.getJob(), "/")]
	jobEnv, err := readConfFile("/jobs/" + project + "/job.conf")
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	result = append(result, jobEnv...)
	return result
}

func readConfFile(fileName string) ([]string, error) {
	file, err := os.Open(os.Getenv("cis_base_dir") + fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	lines := make([]string, 0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func getEnvVars(h *hook) []string {
	from := h.getFromUrl()
	result := make([]string, 0)
	result = append(result,
		"webhook_query_string="+from,
		"webhook_event_type="+getEventType(),
		"webhook_request_body="+h.getBaseDir()+h.getRequestBodyPath())
	args := strings.Split(from[strings.Index(from, "?")+1:], "&")
	return append(result, args...)
}

func getEventType() string {
	return ""
}

func RunSsh(h *hook) int {
	envVars := make([]string, 0)
	envVars = append(envVars, readEnvVarsFromCisOnSsh(h)...)
	envVars = append(envVars, getEnvVars(h)...)
	out := getOutOfSshCommand(h, h.getBaseDir()+"core/$startjob "+h.getJob(), envVars...)
	if strings.Index(out, "Exit code: 0") != -1 {
		return http.StatusOK
	}
	return http.StatusBadRequest
}

func getParams() (out Params) {
	jsonData, err := ioutil.ReadFile("config.json")
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	err = json.Unmarshal(jsonData, &out)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	return out
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

func IsValidPayload(secret, headerHash string, payload []byte) bool {
	hash := "sha1=" + HashPayload(secret, payload)
	return hmac.Equal(
		[]byte(hash),
		[]byte(headerHash),
	)
}

func HashPayload(secret string, playloadBody []byte) string {
	hm := hmac.New(sha1.New, []byte(secret))
	hm.Write(playloadBody)
	sum := hm.Sum(nil)
	return fmt.Sprintf("%x", sum)
}

func main() {
	params = getParams()
	r := mux.NewRouter()
	r.HandleFunc("/users/{username}/webhooks/{platform}/{project}/{job}", сatchHook)
	http.Handle("/", r)
	fmt.Println("starting server at " + params.Port)
	http.ListenAndServe(params.Port, nil)
}
