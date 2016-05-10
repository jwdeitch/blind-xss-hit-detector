package main

import (
	"fmt"
	"time"
	"net/http"
	"github.com/emirozer/go-helpers"
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
	logVisit(r)
	if val, ok := r.URL.Query()["ne"]; ok {
		if (val[0] == "1") {
			fmt.Println("yes")
		}
	}
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
