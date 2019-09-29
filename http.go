package libsgo

import (
	"time"
	"strings"
	"net/http"
	"net/url"
)

func NewHttpLib() *httpLib {
	return &httpLib{}
}

type httpLib struct {
	headers map[string]string
}

func (lib *httpLib) RequestGet(urlAddress string) (*http.Response, error) {
	// 准备
	req, err := http.NewRequest("GET", urlAddress, strings.NewReader(""))
	if err != nil {
		return nil, err
	}
	// set header
	for k, v := range lib.GetHeaders() {
		req.Header.Set(string(k), v)
	}

	// 发起
	client := &http.Client{Timeout: time.Second * 10,}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	// defer resp.Body.Close()
	return resp, nil
}

func (lib *httpLib) RequestPost(urlAddress string, param map[string]string) (*http.Response, error) {
	var data = url.Values{}

	// 准备
	for k, v := range param {
		data.Set(k, v)
	}

	req, err := http.NewRequest("POST", urlAddress, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	// set header
	for k, v := range lib.GetHeaders() {
		req.Header.Set(string(k), v)
	}

	// 发起
	client := &http.Client{Timeout: time.Second * 10,}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	//defer resp.Body.Close()
	return resp, nil
}

func (lib *httpLib) SetHeaders(headers map[string]string) {
	lib.headers = headers
}

func (lib *httpLib) GetHeaders() map[string]string {
	headers := make(map[string]string)
	headers["Accept"] = "*/*"
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	headers["User-Agent"] = "goHttpLib/1.1"
	for k, v := range lib.headers {
		headers[k] = v
	}
	return headers
}
