// Package accesstoken implements getting a token from TIBCO Cloud Mashery
package accesstoken

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"
)

const (
	grantType      = "password"
	ivUsername     = "username"
	ivPassword     = "password"
	ivBasicAuth    = "basicauth"
	ivUrl          = "accessUrl"
	ovToken        = "accesstoken"
	ovTokenType    = "tokentype"
)

// log is the default package logger
var log = logger.GetLogger("activity-accesstoken")

// MyActivity is a stub for your Activity implementation
type MyActivity struct {
	metadata *activity.Metadata
}

// NewActivity creates a new activity
func NewActivity(metadata *activity.Metadata) activity.Activity {
	return &MyActivity{metadata: metadata}
}

// Metadata implements activity.Activity.Metadata
func (a *MyActivity) Metadata() *activity.Metadata {
	return a.metadata
}

// Eval implements activity.Activity.Eval
func (a *MyActivity) Eval(context activity.Context) (done bool, err error) {

	// Get the user provided data
	username := context.GetInput(ivUsername).(string)
	password := context.GetInput(ivPassword).(string)
	url := context.GetInput(ivUrl).(string)
	auth := context.GetInput(ivBasicAuth).(string)
	encodedAuth := b64.StdEncoding.EncodeToString([]byte(auth))

	// Get the token from TIBCO Cloud Mashery
	payload := strings.NewReader(fmt.Sprintf("grant_type=%s&username=%s&password=%s", grantType, username, password))

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return false, err
	}

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("authorization", fmt.Sprintf("Basic %s", encodedAuth))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return false, err
	}

	// Set the output value in the context
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return false, err
	}
	context.SetOutput(ovToken, data["access_token"])
	context.SetOutput(ovTokenType, data["token_type"])

	return true, nil
}
