package libsgo

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

func NewHttpLib() *HttpLib {
	return &HttpLib{
		timeout: time.Second * 20,
	}
}

type HttpLib struct {
	headers map[string]string
	timeout time.Duration
}

func (lib *HttpLib) RequestGet(urlAddress string) (*http.Response, error) {
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
	client := &http.Client{Timeout: lib.timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	// defer resp.Body.Close()
	return resp, nil
}

func (lib *HttpLib) RequestPost(urlAddress string, param map[string]string) (*http.Response, error) {
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
	client := &http.Client{Timeout: lib.timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	//defer resp.Body.Close()
	return resp, nil
}

func (lib *HttpLib) SetHeaders(headers map[string]string) {
	lib.headers = headers
}

func (lib *HttpLib) GetHeaders() map[string]string {
	headers := make(map[string]string)
	headers["Accept"] = "*/*"
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	headers["User-Agent"] = "zLabHttp/1.2"
	for k, v := range lib.headers {
		headers[k] = v
	}
	return headers
}

func (lib *HttpLib) SetTimeout(timeout time.Duration) {
	lib.timeout = timeout
}
