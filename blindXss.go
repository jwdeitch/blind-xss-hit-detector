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
	"os"
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
	Referer           string
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

	// Let's start a timer of 10 minutes once the first request comes in
	var requestBuffer []*http.Request

	if len(requestBuffer) == 0 {
		timer := time.NewTimer(time.Minute * 10)
		go batchSendoff(requestBuffer, timer)
	}

	append(requestBuffer, r)
	for _, req := range requestBuffer {
		sendEmail(req)
	}
}

func batchSendoff(requestBuffer []*http.Request, timer *time.Timer) {
	<-timer.C
	buildEmailBody(requestBuffer)
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
		Referer: r.Referer(),
		Method: r.Method,
	}
}

func buildEmailBody(requestBuffer []*http.Request) {
	var finalBody string
	for _, req := range requestBuffer {
		finalBody = finalBody + json.MarshalIndent(getVisitor(req), "", "	") + "\r\n"
	}
	return sendEmail(finalBody)
}

func sendEmail(body string) {
	creds := credentials.NewEnvCredentials()

	svc := ses.New(session.New(), &aws.Config{
		Region: aws.String("us-west-2"),
		Credentials: creds})

	_, sendErr := svc.SendEmail(&ses.SendEmailInput{
		Destination : &ses.Destination{
			ToAddresses : []*string{
				aws.String(os.Getenv("XSS_CONTACT_EMAIL"))}},
		Message : &ses.Message{Body: &ses.Body{
			Text: &ses.Content{
				Data: aws.String(body),
			},
		},
			Subject: &ses.Content{
				Data: aws.String("Blind XSS triggered"),
			},
		},
		Source : aws.String(os.Getenv("XSS_CONTACT_EMAIL"))})

	if sendErr != nil {
		fmt.Println("email failed to send: " + sendErr.Error())
		return
	}

	fmt.Println("email sent successfully")
}
