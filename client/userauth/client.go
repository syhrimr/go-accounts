package userauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func (u *AuthClient) GetUserInfo(accessToken string) *User {
	client := &http.Client{
		Timeout: u.timeout,
	}

	req, err := http.NewRequest("GET", u.host+"/user/info", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("X-Access-Token", accessToken)

	respRaw, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer respRaw.Body.Close()

	if err != nil {
		return nil
	}

	if respRaw.StatusCode != 200 {
		return nil
	}

	respByte, err := ioutil.ReadAll(respRaw.Body)
	if err != nil {
		log.Print(err)
		return nil
	}

	var resp struct {
		Err  string `json:"err"`
		Data User   `json:"data"`
	}

	err = json.Unmarshal(respByte, &resp)
	if err != nil {
		return nil
	}

	return &resp.Data
}

func (u *AuthClient) GetUserByID(userID int64) *User {
	client := &http.Client{
		Timeout: u.timeout,
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/usr/%d", u.host, userID), nil)
	if err != nil {
		return nil
	}

	respRaw, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer respRaw.Body.Close()

	if err != nil {
		return nil
	}

	if respRaw.StatusCode != 200 {
		return nil
	}

	respByte, err := ioutil.ReadAll(respRaw.Body)
	if err != nil {
		log.Print(err)
		return nil
	}

	var resp struct {
		Err  string `json:"err"`
		Data User   `json:"data"`
	}

	err = json.Unmarshal(respByte, &resp)
	if err != nil {
		return nil
	}

	return &resp.Data
}
