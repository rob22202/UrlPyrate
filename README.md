UrlPyrate
=========

UrlPyrate Version 1.0
UrlPyrate 200s every/any HTTP request, serving default content.  
Use with a DNS blackhole for funtimes.

This script was written by rob22202@gmail.com @rob22202 
and inspired by Fakenet http://practicalmalwareanalysis.com/fakenet/

The script is untested for vulnerabilities.  Caveat Emptor.

Please feel free to use and improve.

Url Pyrate is designed to be used with DNS manipulation.  Redirect your favorite 
malicious domain to the server running UrlPyrate via a DNS blackhole. Then, 
sit back and watch the requests being made to that domain.  Extra fun is 
provided by looking at the referrer field.  That will show you what site linked 
to the malicious domain directly or via a hidden embedded iframe.  Have fun.

UrlPyrate listens with a simple web server on ports 80 and 443, by default.

UrlPyrate will return a 200 to any request it is given, by default it will always 
return the contents of 1.html to the requestor.  Any file placed in the running 
directory of the app with the name "1" ,followed by an appropriate extension will 
be served if a file with that same extension is requested.

At a minimum, This script requires that a SSL certificate named server.pem and a 
default content file named 1.html exist in the same directory from whish it is run.
SSL certificate creation:  openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes

UrlPyrate ouputs pipe delimited logs to UrlPyrate.log, in directory from which it was run.
