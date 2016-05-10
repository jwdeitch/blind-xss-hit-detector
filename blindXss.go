package main

import (
	"fmt"
	"time"
	"net/http"
	"github.com/emirozer/go-helpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/credentials"
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
	sendEmail()
}

func logVisit(r *http.Request) {
	visitor := Visit{
		Visitor: Visitor{
			RemoteAddr:r.RemoteAddr,
			ForwardedFor:r.Header.Get("X-FORWARDED-FOR"),
			Time:time.Now().Unix(),
			UserAgent:r.UserAgent(),
		},
		RequestedResource: r.URL.Path,
		Method: r.Method,
	}
	fmt.Println(visitor)
}

func sendEmail(r *http.Request) {
	creds := credentials.NewEnvCredentials()

	svc := ses.New(session.New(), &aws.Config{
		Region: aws.String("us-west-2"),
		Credentials: creds})


	svc.SendEmail(ses.SendEmailInput{
		"Destination" : ses.Destination{"ToAddresses" : ["test@test.com"]}})

}
