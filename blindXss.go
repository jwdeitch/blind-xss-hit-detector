package main

// Detects hits to /hackerone/xss, will log and email hit

import (
	"fmt"
	"time"
	"net/http"
	"github.com/emirozer/go-helpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"encoding/json"
)

type Visitor struct {
	RemoteAddr   string
	ForwardedFor string
	Time         int64
	UserAgent    string
}

type Visit struct {
	Visitor           Visitor
	RequestedResource string
	Method            string
}

func main() {
	fmt.Println("We're up and running")
	http.HandleFunc("/hackerone/xss", capture)
	err := http.ListenAndServe(":9090", nil)
	helpers.Check(err)
}

func capture(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "This page is intended to detect blind XSS vulnerabilities in the spirit of your organizations bug bounty program.")
	logVisit(r)
	if val, ok := r.URL.Query()["ne"]; ok {
		if (val[0] == "1") {
			fmt.Println("No email sent")
			return
		}
	}
	sendEmail(r)
}

func logVisit(r *http.Request) {
	fmt.Println(getVisitor(r))
}

func getVisitor(r *http.Request) Visit {
	return Visit{
		Visitor: Visitor{
			RemoteAddr:r.RemoteAddr,
			ForwardedFor:r.Header.Get("X-FORWARDED-FOR"),
			Time:time.Now().Unix(),
			UserAgent:r.UserAgent(),
		},
		RequestedResource: r.URL.Path,
		Method: r.Method,
	}
}

func sendEmail(r *http.Request) {
	creds := credentials.NewEnvCredentials()

	svc := ses.New(session.New(), &aws.Config{
		Region: aws.String("us-west-2"),
		Credentials: creds})

	rawRequest, _ := json.Marshal(getVisitor(r))
	msgBody := "XSS triggered from: " + r.Referer() + "\r\n \r\n \r\n " + string(rawRequest)

	svc.SendEmail(&ses.SendEmailInput{
		Destination : &ses.Destination{
			ToAddresses : []*string{
				aws.String("test@test.com")}},
		Message : &ses.Message{Body: &ses.Body{// Required
			Text: &ses.Content{
				Data: aws.String(msgBody), // Required
			},
		}, },
		Source : aws.String("xss@r.ps")})
	fmt.Println("email sent")
}
