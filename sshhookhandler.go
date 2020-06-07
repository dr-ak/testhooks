package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"strings"

	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type SSHHookHandler struct {
	FromUrl         string
	HookType        string
	Address         string
	Port            string
	User            string
	BaseDir         string
	Job             string
	RequestBodyPath string
}

func (h SSHHookHandler) getFromUrl() string {
	return h.FromUrl
}

func (h SSHHookHandler) getType() string {
	return h.HookType
}

func (h SSHHookHandler) getAddress() string {
	return h.Address
}

func (h SSHHookHandler) getPort() string {
	return h.Port
}

func (h SSHHookHandler) getUser() string {
	return h.User
}

func (h SSHHookHandler) getBaseDir() string {
	return h.BaseDir
}

func (h SSHHookHandler) getJob() string {
	return h.Job
}

func (h SSHHookHandler) getRequestBodyPath() string {
	return h.RequestBodyPath
}

func (h SSHHookHandler) handle(w http.ResponseWriter, r *http.Request, body []byte) bool {
	pwd, err := os.Getwd()
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	from := pwd + "/request_body.json"
	to := h.getBaseDir() + h.getRequestBodyPath()
	writeFile(from, body)
	h.moveFileOnSsh(from, to)
	status := h.run()
	if status == http.StatusOK {
		return true
	}
	w.WriteHeader(status)
	return false
}

func (h SSHHookHandler) run() int {
	envVars := make([]string, 0)
	envVars = append(envVars, h.readEnvVarsFromCisOnSsh()...)
	envVars = append(envVars, h.getEnvVars()...)
	out := h.getOutOfSshCommand(h.getBaseDir()+"core/$startjob "+h.getJob(), envVars...)
	fmt.Println(out)
	if strings.Index(out, "Exit code: 0") != -1 {
		return http.StatusOK
	}
	return http.StatusBadRequest
}

func (h SSHHookHandler) getOutOfSshCommand(command string, envVars ...string) string {
	session, err := h.getSshSession()
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

func (h SSHHookHandler) readEnvVarsFromCisOnSsh() []string {
	result := make([]string, 0)
	cisEnv := strings.Split(h.getOutOfSshCommand("cat "+h.getBaseDir()+"/core/cis.conf"), "\n")
	result = append(result, cisEnv...)
	project := h.getJob()[:strings.Index(h.getJob(), "/")]
	jobEnv := strings.Split(h.getOutOfSshCommand("cat "+h.getBaseDir()+"/jobs/"+project+"/job.conf"), "\n")
	result = append(result, jobEnv...)
	return result
}

func (h SSHHookHandler) getEnvVars() []string {
	from := h.getFromUrl()
	result := make([]string, 0)
	result = append(result,
		"webhook_query_string="+from,
		"webhook_event_type="+getEventType(),
		"webhook_request_body="+h.getBaseDir()+h.getRequestBodyPath())
	args := strings.Split(from[strings.Index(from, "?")+1:], "&")
	return append(result, args...)
}

func (h SSHHookHandler) moveFileOnSsh(from, to string) {
	session, err := h.getSshSession()
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

func (h SSHHookHandler) getClientConfig() *ssh.ClientConfig {
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

func (h SSHHookHandler) getSshSession() (*ssh.Session, error) {
	client, err := ssh.Dial("tcp", h.getAddress()+":"+h.getPort(), h.getClientConfig())
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	session, err := client.NewSession()
	return session, err
}
