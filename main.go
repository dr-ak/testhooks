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
	"strings"

	"github.com/gorilla/mux"
	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var params Params

type hook struct {
	From string
	To   string
}

type Params struct {
	Port            string
	Hooks           []hook
	Root            string
	RequestBodyPath string
	keyHook         int
	eventType       string
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

func (p Params) getJobName() string {
	url := p.Hooks[p.keyHook].From[0:strings.Index(p.Hooks[p.keyHook].From, "?")]
	return url[strings.LastIndex(url, "/")+1:]
}

func (p Params) getRequestBodyPath() string {
	return strings.Replace(p.RequestBodyPath, "$job", p.getJobName(), -1)
}

func (p Params) getHookTo() string {
	return p.Hooks[p.keyHook].To
}

func (p *Params) setEvenType(eventType string) {
	p.eventType = eventType
}

func (p *Params) setKeyHook(url string) bool {
	for key, hook := range p.Hooks {
		if hook.From == url {
			p.keyHook = key
			return true
		}
	}
	return false
}

func (p Params) getEnvVars() []string {
	from := p.Hooks[p.keyHook].From
	result := make([]string, 0)
	result = append(result,
		"webhook_query_string="+from,
		"webhook_event_type="+p.eventType,
		"webhook_request_body=$cis_base_dir"+p.getRequestBodyPath())
	args := strings.Split(from[strings.Index(from, "?")+1:], "&")
	return append(result, args...)
}

func (p Params) readEnvVarsFromCis() []string {
	result := make([]string, 0)
	cisEnv, err := p.readConfFile("/core/cis.conf")
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	result = append(result, cisEnv...)
	jobEnv, err := p.readConfFile("/jobs/internal/" + p.getJobName() + "/job.conf")
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	result = append(result, jobEnv...)
	return result
}

func (p Params) readConfFile(fileName string) ([]string, error) {
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

func (p Params) readEnvVarsFromCisOnSsh() []string {
	result := make([]string, 0)
	base_dir := getOutOfSshCommand(p, "echo $cis_base_dir")
	cisEnv := strings.Split(getOutOfSshCommand(p, "cat "+base_dir+"/core/cis.conf"), "\n")
	result = append(result, cisEnv...)
	jobEnv := strings.Split(getOutOfSshCommand(p, "cat "+base_dir+"/jobs/internal/"+p.getJobName()+"/job.conf"), "\n")
	result = append(result, jobEnv...)
	return result
}

type SshParams struct {
	User   string
	Host   string
	Port   string
	Launch string
}

func getSshParams(cmd string) *SshParams {
	result := &SshParams{}
	params := strings.Split(cmd, " ")
	for i, param := range params {
		if strings.Contains(param, "@") {
			temp := strings.Split(param, "@")
			result.User = temp[0]
			result.Host = temp[1]
		} else if strings.Compare(strings.ToLower(param), "-p") == 0 {
			result.Port = params[i+1]
		} else if i == len(params)-2 {
			result.Launch = param + " " + params[i+1]
		}
	}
	return result
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

func RunLocal(p Params) int {
	envVars := make([]string, 0)
	envVars = append(envVars, p.readEnvVarsFromCis()...)
	envVars = append(envVars, p.getEnvVars()...)
	command := strings.Split(p.getHookTo(), " ")
	path := buildPath(command[0], envVars)
	cmd := exec.Command(path, command[1:]...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Env = append(os.Environ(), envVars...)
	err := cmd.Run()
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	out := buf.String()[0 : len(buf.String())-1]
	if strings.Index(out, "Exit code: 0") != -1 {
		return http.StatusOK
	}
	return http.StatusBadRequest
}

func getClientConfig(userName string) *ssh.ClientConfig {
	key, err := ioutil.ReadFile(os.Getenv("HOME") + "/.ssh/id_rsa")
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	hostKeyCallback, err := knownhosts.New(os.Getenv("HOME") + "/.ssh/known_hosts")
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	return &ssh.ClientConfig{
		User: userName,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
	}
}

func buildPath(path string, envVars []string) string {
	for _, envVar := range envVars {
		if strings.HasPrefix(envVar, "startjob") {
			os.Setenv("startjob", envVar[strings.Index(envVar, "=")+1:])
			break
		}
	}
	pathAsArr := strings.Split(path, "/")
	for key, item := range pathAsArr {
		if strings.HasPrefix(item, "$") {
			pathAsArr[key] = os.Getenv(item[1:])
		}
	}
	return strings.Join(pathAsArr, "/")
}

func RunSsh(p Params) int {
	sshParams := getSshParams(p.getHookTo())
	client, err := ssh.Dial("tcp", sshParams.Host+":"+sshParams.Port, getClientConfig(sshParams.User))
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	session, err := client.NewSession()
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	defer session.Close()
	envVars := make([]string, 0)
	envVars = append(envVars, p.readEnvVarsFromCisOnSsh()...)
	envVars = append(envVars, p.getEnvVars()...)

	for _, envVar := range envVars {
		envAsArr := strings.Split(envVar, "=")
		err := session.Setenv(envAsArr[0], envAsArr[1])
		if err != nil {
			fmt.Println(err.Error())
		}
	}
	b, err := session.CombinedOutput(sshParams.Launch)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	if strings.Index(string(b), "Exit code: 0") != -1 {
		return http.StatusOK
	}
	return http.StatusBadRequest
}

func getOutOfSshCommand(p Params, command string) string {
	sshParams := getSshParams(p.getHookTo())
	client, err := ssh.Dial("tcp", sshParams.Host+":"+sshParams.Port, getClientConfig(sshParams.User))
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	session, err := client.NewSession()
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	defer session.Close()
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

func moveFileOnSsh(p Params, from, to string) {
	sshParams := getSshParams(p.getHookTo())
	client, err := ssh.Dial("tcp", sshParams.Host+":"+sshParams.Port, getClientConfig(sshParams.User))
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	session, err := client.NewSession()
	defer session.Close()
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	err = scp.CopyPath(from, to, session)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	err = os.Remove(from)
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
}

func сatchHook(w http.ResponseWriter, r *http.Request) {
	url := "http://" + r.Host + r.URL.String()
	success := "false"
	if params.setKeyHook(url) {
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
		if strings.HasPrefix(params.getHookTo(), "http") {
			client := &http.Client{}
			req, err := http.NewRequest(r.Method, params.getHookTo(), r.Body)
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
		} else if strings.HasPrefix(params.getHookTo(), "ssh") {
			from := params.Root + "request_body.json"
			to := getOutOfSshCommand(params, "echo $cis_base_dir") + params.getRequestBodyPath()
			writeFile(from, body)
			moveFileOnSsh(params, from, to)
			writeFile(os.Getenv("cis_base_dir")+params.getRequestBodyPath(), body)
			status := RunSsh(params)
			if status == http.StatusOK {
				success = "true"
			}
			w.WriteHeader(status)
		} else {
			writeFile(os.Getenv("cis_base_dir")+params.getRequestBodyPath(), body)
			status := RunLocal(params)
			if status == http.StatusOK {
				success = "true"
			}
			w.WriteHeader(status)
		}
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

func main() {
	params = getParams()
	r := mux.NewRouter()
	r.HandleFunc("/users/{username}/webhooks/{platform}/{project}/{job}", сatchHook)
	http.Handle("/", r)
	fmt.Println("starting server at " + params.Port)
	http.ListenAndServe(params.Port, nil)
}
