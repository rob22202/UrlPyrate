#!/usr/bin/python

# UrlPyrate Version 1.0
# UrlPyrate (aka PerfectGirlfriend) 200s every/any HTTP request, serving default content.  
# Use with a DNS blackhole for funtimes.

# This script was written by rob22202@gmail.com @rob22202 
# and inspired by Fakenet http://practicalmalwareanalysis.com/fakenet/

# This script is not intended to be use don the internet, as it is 
# untested for vulnerabilities.  Caveat Emptor.

# Please feel free to use and improve.

# Url Pyrate is designed to be used with DNS manipulation.  Redirect your favorite 
# malicious domain to the server running UrlPyrate via a DNS blackhole. Then, 
# sit back and watch the requests being made to that domain.  Extra fun is 
# provided by looking at the referrer field.  That will show you what site linked 
# to the malicious domain directly or via a hidden embedded iframe.  Have fun.

# UrlPyrate listens with a simple web server on ports 80 and 443, by default.

# UrlPyrate will return a 200 to any request it is given, by default it will always 
# return the contents of 1.html to the requestor.  Any file placed in the running 
# directory of the app with the name "1" ,followed by an appropriate extension will 
# be served if a file with that same extension is requested.

# At a minimum, This script requires that a SSL certificate named server.pem and a 
# default content file named 1.html exist in the same directory from whish it is run.

# SSL certificate creation:  openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes

# UrlPyrate ouputs pipe delimited logs to UrlPyrate.log, in directory from which it was run.

import SimpleHTTPServer, os, BaseHTTPServer, ssl, sys
from multiprocessing import Process

logfile = 'UrlPyrate.log'

def main():
  http_port = 80
	https_port = 4443
	with open(logfile, 'a') as log:
			print >> log, 'date|source_ip|source_port|source_name|host|command|path|referer|accept|accept_charset|accept_encoding|accept_language|connection|cookie|user_agent'
			print >> log, ''
	if len(sys.argv) == 3:
		http_port = int(sys.argv[1])
		https_port = int(sys.argv[2])
		
	https_server = Process(name='https_server', target=run_https_server, args=(https_port,))
	http_server = Process(name='http_server', target=run_http_server, args=(http_port,))
	https_server.start()
	http_server.start()
	
def run_https_server(https_port):
	print "Serving HTTPS on port %d" % (https_port)
	try:
		httpd = BaseHTTPServer.HTTPServer(
				('', https_port),
				SimplerHTTPRequestHandler )
		httpd.socket = ssl.wrap_socket(
				httpd.socket,
				certfile='server.pem',
				server_side=True )
		httpd.serve_forever()
	except SSLError:
		print 'SSL Error'
		pass
		
def run_http_server(http_port):
	print "Serving HTTP on port %d" % (http_port)
	httpd = BaseHTTPServer.HTTPServer(
			('', http_port),
			SimplerHTTPRequestHandler )
	httpd.serve_forever()

class SimplerHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
	def send_head(self):
		var_date = self.log_date_time_string()
		var_source_ip = str(self.client_address[0])
		var_source_port = str(self.client_address[1])
		var_source_name = self.address_string()
		var_host = str(self.headers.getheader('host'))
		var_command = self.command
		var_path = self.path
		var_referer = str(self.headers.getheader('referer'))
		var_accept = str(self.headers.getheader('accept'))
		var_accept_charset = str(self.headers.getheader('accept-charset'))
		var_accept_encoding = str(self.headers.getheader('accept-encoding'))
		var_accept_language = str(self.headers.getheader('accept-language'))
		var_connection = str(self.headers.getheader('connection'))
		var_cookie = str(self.headers.getheader('cookie'))
		var_user_agent = str(self.headers.getheader('user-agent'))
		
		with open(logfile, 'a') as log:
			print >> log, var_date+'|'+var_source_ip+'|'+var_source_port+'|'+var_source_name+'|'+var_host+'|'+var_command+'|'+var_path+'|'+var_referer+'|'+var_accept+'|'+var_accept_charset+'|'+var_accept_encoding+'|'+var_accept_language+'|'+var_connection+'|'+var_cookie+'|'+var_user_agent
			print >> log, ''

		(name,ext) = os.path.splitext(self.path)

		path = self.translate_path("1%s" % ext)

		if not os.path.exists(path):
			path = self.translate_path("1.html")

		ctype = self.guess_type(path)
		if ctype.startswith('text/'):
			mode = 'r'
		else:
			mode = 'rb'

		try:
			f = open(path, mode)
		except IOError:
			self.send_error(404, "File not found")
			return None

		self.send_response(200)
		self.send_header("Content-type", ctype)
		self.end_headers()
		return f

if __name__ == "__main__":
	main()
