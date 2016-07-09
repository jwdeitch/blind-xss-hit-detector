package main

// Detects hits to /s, will log and email hit

import (
	"fmt"
	"time"
	"net/http"
	"github.com/inturn/go-helpers"
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
	http.HandleFunc("/s", capture)
	err := http.ListenAndServe(":9090", nil)
	helpers.Check(err)
}

// This slice will be built up to store the requests in 10 minute intervals
var requestBuffer []*http.Request

// A query param of ne (no email) set to 1 will not add the request to the requestBuffer.
func capture(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "This page is intended to detect blind XSS vulnerabilities in the spirit of your organizations bug bounty program.")
	logVisit(r)
	if val, ok := r.URL.Query()["ne"]; ok {
		if (val[0] == "1") {
			fmt.Println("No email sent")
			return
		}
	}

	if len(requestBuffer) == 0 {
		timer := time.NewTimer(time.Hour/4)
		go batchSendoff(&requestBuffer, timer)
	}

	requestBuffer = append(requestBuffer, r)

}

// This will block until timer channel sends
func batchSendoff(requestBuffer *[]*http.Request, timer *time.Timer) {
	<-timer.C
	buildEmailBody(requestBuffer)
}

// Write all visits to stdout
func logVisit(r *http.Request) {
	fmt.Println(getVisitor(r))
}

// creates new visit structure
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

// Iterate over the request slice to build email body
func buildEmailBody(requestBuffer *[]*http.Request) {
	var finalBody string
	for _, req := range *requestBuffer {
		jsonSerializedBody, _ := json.MarshalIndent(getVisitor(req), "", "	")
		finalBody = finalBody + string(jsonSerializedBody) + "\r\n"
	}
	sendEmail(finalBody)
}

// Send email from provided body string
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

	requestBuffer = requestBuffer[:0]

	fmt.Println("email sent successfully")
}
