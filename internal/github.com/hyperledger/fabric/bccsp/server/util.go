package server

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

func httpRequestJSON(httpType, url string, data interface{}) (*ResponseCA, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	jsonStr, err := json.Marshal(data)
	if err != nil {
		return nil, errors.Wrap(err, "json.Marshal(data)")
	}

	req, err := http.NewRequest(httpType, url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, errors.Wrap(err, "http.NewRequest(httpType, url, bytes.NewBuffer(jsonStr))")
	}
	defer req.Body.Close()

	req.Header.Add("content-type", "application/json")
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "client.Do(req)")
	}
	defer resp.Body.Close()

	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "ioutil.ReadAll(resp.Body)")
	}

	response := &ResponseCA{}
	if err := json.Unmarshal(result, response); err != nil {
		return nil, errors.Wrap(err, "json.Unmarshal(result, response);")
	}

	if response.Status != "1" {
		return nil, errors.New(string(result))
	}
	return response, nil
}
