package main

import (
        "crypto/tls"
        "flag"
        "fmt"
        "log"
        "net/http"
        "strings"
        "time"

        cp "github.com/fatih/color"
)

// https://github.com/glidasion/h2t

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
var detailFlag = flag.Bool("details", false, "Show detailed info")

func main() {
        log.SetFlags(0)

        flag.Parse()

        if *urlFlag == "" {
                flag.PrintDefaults()
                return
        }

        tr := &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        }
        client := &http.Client{Transport: tr}

        response, err := client.Get(*urlFlag)
        if err != nil {
                log.Fatal(err)
        }

        defer response.Body.Close()

        cp.Magenta("\nChecking \"%s\" for security configuration issues", *urlFlag)
        cp.Blue("Tested on: %s\n\n", time.Now().Format(time.RFC1123))

        checkForHeader(response.Header)

        fmt.Println("")

        checkCookies(response.Cookies())

        fmt.Println("")
}

func checkForHeader(header map[string][]string) {
        fmt.Println("")
        cp.Set(cp.FgBlack)
        cp.Set(cp.BgWhite)
        fmt.Println("== HEADER AUDIT ==")
        cp.Unset()

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
                        cp.Green("[✔️] %s (%v)", k, header[k])
                } else {
                        cp.Red("[✖️] %s (Not present)", k)
                }

                if *detailFlag {
                        cp.Blue("%s", secHeaders[k])
                        fmt.Println("")
                }
        }

        fmt.Println("")
        cp.Set(cp.FgBlack)
        cp.Set(cp.BgWhite)
        fmt.Println("== RAW HEADERS ==")
        cp.Unset()



        for k, v := range header {
                cp.Set(cp.FgCyan)
                fmt.Printf("%s: ", k)
                cp.Unset()
                for i := range v {
                        fmt.Printf("%s ", v[i])
                }
                fmt.Println("")
        }
}

func checkCookies(cookies []*http.Cookie) {
        cp.Set(cp.FgBlack)
        cp.Set(cp.BgWhite)
        fmt.Println("== COOKIE AUDIT ==")
        cp.Unset()

        for i := range cookies {
                c := cookies[i]

                if !c.Secure || !c.HttpOnly {
                        cp.Set(cp.FgCyan)
                        fmt.Printf(c.Name)
                        cp.Unset()

                        if !c.Secure {
                                fmt.Printf(" Missing \"")
                                cp.Set(cp.FgRed)
                                fmt.Printf("Secure")
                                cp.Unset()
                                fmt.Printf("\" attribute;")
                        }

                        if !c.HttpOnly {
                                fmt.Printf(" Missing \"")
                                cp.Set(cp.FgRed)
                                fmt.Printf("HttpOnly")
                                cp.Unset()
                                fmt.Printf("\" attribute;")
                        }
                }

                fmt.Println("")
        }

        fmt.Println("")
        cp.Set(cp.FgBlack)
        cp.Set(cp.BgWhite)
        fmt.Println("== RAW COOKIES ==")
        cp.Unset()

        for i := range cookies {
                fmt.Println(cookies[i])
        }
}
