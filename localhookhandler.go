package main

import (
	"bufio"
	"bytes"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type LocalHookHandler struct {
	FromUrl         string
	HookType        string
	BaseDir         string
	Job             string
	RequestBodyPath string
}

func (h LocalHookHandler) getFromUrl() string {
	return h.FromUrl
}

func (h LocalHookHandler) getType() string {
	return h.HookType
}

func (h LocalHookHandler) getBaseDir() string {
	return h.BaseDir
}

func (h LocalHookHandler) getJob() string {
	return h.Job
}

func (h LocalHookHandler) getRequestBodyPath() string {
	return h.RequestBodyPath
}

func (h LocalHookHandler) handle(w http.ResponseWriter, r *http.Request, body []byte) bool {
	writeFile(os.Getenv("cis_base_dir")+"/"+h.getRequestBodyPath(), body)
	status := h.run()
	if status == http.StatusOK {
		return true
	}
	w.WriteHeader(status)
	return false
}

func (h LocalHookHandler) run() int {
	envVars := make([]string, 0)
	envVars = append(envVars, h.readEnvVarsFromCis()...)
	envVars = append(envVars, h.getEnvVars()...)
	command := h.getBaseDir() + "/core/" + h.getStartJob(envVars)
	cmd := exec.Command(command, h.getJob())
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

func (h LocalHookHandler) readEnvVarsFromCis() []string {
	result := make([]string, 0)
	cisEnv, err := h.readConfFile("/core/cis.conf")
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	result = append(result, cisEnv...)
	project := h.getJob()[:strings.Index(h.getJob(), "/")]
	jobEnv, err := h.readConfFile("/jobs/" + project + "/job.conf")
	if err != nil {
		writeLog("logs/error.log", err.Error())
	}
	result = append(result, jobEnv...)
	return result
}

func (h LocalHookHandler) readConfFile(fileName string) ([]string, error) {
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

func (h LocalHookHandler) getEnvVars() []string {
	from := h.getFromUrl()
	result := make([]string, 0)
	result = append(result,
		"webhook_query_string="+from,
		"webhook_event_type="+getEventType(),
		"webhook_request_body="+h.getBaseDir()+h.getRequestBodyPath())
	args := strings.Split(from[strings.Index(from, "?")+1:], "&")
	return append(result, args...)
}

func (h LocalHookHandler) getStartJob(envVars []string) string {
	for _, envVar := range envVars {
		if strings.HasPrefix(envVar, "startjob") {
			return envVar[strings.Index(envVar, "=")+1:]
		}
	}
	return ""
}
