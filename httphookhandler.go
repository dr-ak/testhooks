package main

import (
	"bytes"
	"net/http"
)

type HTTPHookHandler struct {
	FromUrl  string
	HookType string
	ToUrl    string
}

func (h HTTPHookHandler) getFromUrl() string {
	return h.FromUrl
}

func (h HTTPHookHandler) getType() string {
	return h.HookType
}

func (h HTTPHookHandler) getToUrl() string {
	return h.ToUrl
}

func (h HTTPHookHandler) handle(w http.ResponseWriter, r *http.Request, body []byte) bool {
	respBody := bytes.NewReader(body)
	client := &http.Client{}
	req, err := http.NewRequest(r.Method, h.getToUrl(), respBody)
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
		return true
	}
	w.WriteHeader(resp.StatusCode)
	return false
}
