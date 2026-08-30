package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

type GsheetConfig struct {
	CRED_PATH string   `yaml:"CRED_PATH"`
	SHEET_ID  string   `yaml:"SHEET_ID"`
	SHEETS    []string `yaml:"SHEETS"`
}

func GetGsheetConfig() (GsheetConfig, error) {

	var gsh_conf GsheetConfig

	file_b, err := os.ReadFile("./config.yaml")

	if err != nil {

		return gsh_conf, fmt.Errorf("failed to read conf: %s", err.Error())

	}

	err = yaml.Unmarshal(file_b, &gsh_conf)

	if err != nil {

		return gsh_conf, fmt.Errorf("failed to read conf: %s", err.Error())

	}

	return gsh_conf, nil
}

func GetGsheetClient(config *oauth2.Config) (*http.Client, error) {

	var http_client *http.Client

	tokFile := "token.json"
	tok, err := GetGsheetTokenFromFile(tokFile)
	if err != nil {
		tok, err = GetGsheetTokenFromWeb(config)

		if err != nil {

			return http_client, fmt.Errorf("failed to get gsheet client: %s", err.Error())

		}

		SaveGsheetToken(tokFile, tok)
	}

	http_client = config.Client(context.Background(), tok)

	return http_client, nil
}

func GetGsheetTokenFromWeb(config *oauth2.Config) (*oauth2.Token, error) {

	var tok *oauth2.Token

	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)

	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string

	if _, err := fmt.Scan(&authCode); err != nil {

		return tok, fmt.Errorf("failed to get web token: %s", err.Error())
	}

	tok, err := config.Exchange(context.TODO(), authCode)

	if err != nil {
		return tok, fmt.Errorf("unable to retrive token from web: %s", err.Error())
	}

	return tok, nil
}

func GetGsheetTokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

func SaveGsheetToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}
