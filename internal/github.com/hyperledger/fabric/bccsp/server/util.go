package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// ResponseCA response result
type ResponseCA struct {
	Code    string `json:"code"`
	Message string `json:"msg"`
}

func httpRequestJSON(httpType, url string, data interface{}, cookie ...string) (*ResponseCA, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	jsonStr, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to json marshal data, err:%s", err.Error())
	}

	req, err := http.NewRequest(httpType, url, bytes.NewBuffer(jsonStr))
	req.Header.Add("content-type", "application/json")
	if err != nil {
		return nil, fmt.Errorf("failed to new request, err:%s", err.Error())
	}
	defer req.Body.Close()

	req.Close = true
	if len(cookie) > 0 {
		req.Header.Set("Cookie", cookie[0])
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request, err:%s", err.Error())
	}
	defer resp.Body.Close()

	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body, err:%s", err.Error())
	}

	response := &ResponseCA{}
	if err := json.Unmarshal(result, response); err != nil {
		return nil, fmt.Errorf("failed to json unmarshal response ca, err:%s", err.Error())
	}
	return response, nil
}
