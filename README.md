# sct

Security checks for http headers and cookies

## USAGE

```
$ sct -url https://google.com

Checking "https://google.com" for security configuration issues
Tested on: Wed, 11 Sep 2019 13:38:23 CEST

== HEADER AUDIT ==
[✖️] X-Content-Type-Options (Not present)
[✔️] X-XSS-Protection ([0])
[✖️] Referrer-Policy (Not present)
[✖️] Content-Security-Policy (Not present)
[✖️] Feature-Policy (Not present)
[✖️] Strict-Transport-Security (Not present)
[✔️] X-Frame-Options ([SAMEORIGIN])

== RAW HEADERS ==
Set-Cookie: 1P_JAR=[...]; path=/; domain=.google.com; SameSite=none NID=[...]; HttpOnly 
X-Frame-Options: SAMEORIGIN 
Date: Wed, 11 Sep 2019 11:38:23 GMT 
Expires: -1 
Cache-Control: private, max-age=0 
Content-Type: text/html; charset=ISO-8859-1 
P3p: CP="This is not a P3P policy! See g.co/p3phelp for more info." 
Server: gws 
Alt-Svc: quic=":443"; ma=2592000; v="46,43,39" 
X-XSS-Protection: 0 

== COOKIE AUDIT ==
1P_JAR Missing "Secure" attribute; Missing "HttpOnly" attribute;
NID Missing "Secure" attribute;

== RAW COOKIES ==
1P_JAR=2019-09-11-11; Path=/; Domain=google.com; Expires=Fri, 11 Oct 2019 11:38:23 GMT; SameSite=None
NID=[...]; HttpOnly
```  
