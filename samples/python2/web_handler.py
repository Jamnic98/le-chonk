#!/usr/bin/env python2
import BaseHTTPServer, urlparse, cgi

class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urlparse.parse_qs(urlparse.urlparse(self.path).query)
        name = q.get("name", [""])[0]
        if name == "admin":
            print "serving admin page for " + name
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write("<html><body>hi %s</body></html>" % cgi.escape(name))

def run():
    port = input("Port? ")
    srv = BaseHTTPServer.HTTPServer(("0.0.0.0", int(port)), Handler)
    print "listening on", port
    srv.serve_forever()

if __name__ == "__main__":
    run()
