/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at
   http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
*/

package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	yellow  = color.New(color.Bold, color.FgYellow).SprintFunc()
	red     = color.New(color.Bold, color.FgRed).SprintFunc()
	cyan    = color.New(color.Bold, color.FgCyan).SprintFunc()
	green   = color.New(color.Bold, color.FgGreen).SprintFunc()
	blue    = color.New(color.Bold, color.FgBlue).SprintFunc()
	magenta = color.New(color.Bold, color.FgMagenta).SprintFunc()
	black   = color.New(color.FgBlack, color.BgWhite).SprintFunc()
)

var secHeaders = map[string]string{
	"Strict-Transport-Security": "HTTP Strict Transport Security is an excellent feature to support on your site and strengthens your implementation of TLS by getting the User Agent to enforce the use of HTTPS.",
	"X-Frame-Options":           "X-Frame-Options tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking.",
	"X-Content-Type-Options":    "X-Content-Type-Options stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is 'X-Content-Type-Options: nosniff'.",
	"X-XSS-Protection":          "X-XSS-Protection sets the configuration for the cross-site scripting filters built into most browsers. The best configuration is 'X-XSS-Protection: 1; mode=block'.",
	"Referrer-Policy":           "Referrer Policy is a new header that allows a site to control how much information the browser includes with navigations away from a document and should be set by all sites",
	"Content-Security-Policy":   "Content Security Policy is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets. Analyse this policy in more detail. You can sign up for a free account on Report URI to collect reports about problems on your site.",
	"Feature-Policy":            "Feature Policy is a new header that allows a site to control which features and APIs can be used in the browser.",
	// "Access-Control-Allow-Origin": "",
}

var urlFlag = flag.String("url", "", "Url to check")
var urlListFlag = flag.String("urlList", "", "List with Url to check")
var detailFlag = flag.Bool("details", false, "Show detailed info")

func main() {
	log.SetFlags(0)

	flag.Parse()

	if *urlFlag == "" && *urlListFlag == "" {
		flag.PrintDefaults()
		return
	}

	if *urlListFlag != "" {
		file, err := os.Open(*urlListFlag)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fmt.Fprintf(color.Output, "\nChecking %v for security configuration issues\n", magenta(scanner.Text()))
			fmt.Fprintf(color.Output, "Tested on: %v \n\n", blue(time.Now().Format(time.RFC1123)))
			var response = MakeRequest(scanner.Text())
			checkForHeader(response.Header)
			checkCookies(response.Cookies())
			fmt.Fprintf(color.Output, "\n%v\n", yellow("*********"))
		}
	} else {
		fmt.Fprintf(color.Output, "\nChecking %v for security configuration issues\n", magenta(*urlFlag))
		fmt.Fprintf(color.Output, "Tested on: %v \n\n", blue(time.Now().Format(time.RFC1123)))
		var response = MakeRequest(*urlFlag)
		checkForHeader(response.Header)
		checkCookies(response.Cookies())
	}

}

// MakeRequest will do the GET request
// to retrieve the headers
func MakeRequest(host string) *http.Response {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	response, err := client.Get(host)
	if err != nil {
		log.Fatal(err)
	}

	defer response.Body.Close()
	return response

}

// checkForHeader will check every header value
// indicating if it's present or not
func checkForHeader(header map[string][]string) {
	fmt.Fprintf(color.Output, "\n%v", black("== HEADER AUDIT =="))

	for k := range secHeaders {
		available := false
		for h := range header {
			if strings.ToLower(h) == strings.ToLower(k) {
				if len(header[k]) <= 0 {
					header[k] = header[h]
					delete(header, h)
				}

				available = true
				break
			}
		}

		if available {
			fmt.Fprintf(color.Output, "\n%v", green("[✔️] ", k, " ", header[k]))
		} else {
			fmt.Fprintf(color.Output, "\n%v", red("[✖️] ", k, " (Not present)"))
		}

		if *detailFlag {
			fmt.Fprintf(color.Output, " ➡ %v", yellow(secHeaders[k]))
		}
	}

	fmt.Fprintf(color.Output, "\n\n%v\n", black("== RAW HEADERS =="))

	for k, v := range header {
		fmt.Fprintf(color.Output, "%v ", cyan(k, ":"))
		for i := range v {
			fmt.Printf("%s\n", v[i])
		}
	}
}

// checkCookies will check if existing cookies
// have Secure or HttpOnly attribute
func checkCookies(cookies []*http.Cookie) {
	fmt.Fprintf(color.Output, "\n%v", black("== COOKIE AUDIT =="))

	for i := range cookies {
		c := cookies[i]

		if !c.Secure || !c.HttpOnly {
			fmt.Fprintf(color.Output, "\n%v: ", cyan(c.Name))

			if !c.Secure {
				fmt.Fprintf(color.Output, "Missing %v attribute; ", red("Secure"))
			}

			if !c.HttpOnly {
				fmt.Fprintf(color.Output, "Missing %v attribute; ", red("HttpOnly"))
			}
		}
	}

	fmt.Fprintf(color.Output, "\n\n%v\n", black("== RAW COOKIES =="))

	for i := range cookies {
		fmt.Printf("%v \n", cookies[i])
	}
}
