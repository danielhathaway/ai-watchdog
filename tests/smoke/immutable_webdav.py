"""Apply server-side write-once rules to one directory in the WebDAV fixture."""

import http.client
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


class Handler(BaseHTTPRequestHandler):
    def proxy(self):
        relative = Path(unquote(urlsplit(self.path).path).lstrip("/"))
        if ".." in relative.parts:
            self.send_error(400)
            return
        protected = relative.parts[:2] == ("backups", "immutable")
        if self.command == "DELETE" and (protected or relative.parts in ((), ("backups",))):
            self.send_error(403, "Immutable storage denies deletion")
            return
        if self.command == "PUT" and protected:
            # Keep the existence check and write together, including concurrent writers.
            with self.server.writes:
                if (self.server.storage / relative).exists():
                    self.send_error(403, "Immutable storage denies overwrites")
                else:
                    self.forward()
        else:
            self.forward()

    do_GET = do_HEAD = do_PROPFIND = do_MKCOL = do_PUT = do_DELETE = do_OPTIONS = proxy

    def forward(self):
        upstream = http.client.HTTPConnection("127.0.0.1", self.server.backend_port, timeout=20)
        headers = {key: value for key, value in self.headers.items() if key.lower() not in {"connection", "host"}}
        size = int(self.headers.get("Content-Length", 0))
        if self.headers.get("Transfer-Encoding"):
            self.send_error(501, "This fixture requires a fixed-length upload")
            return
        try:
            upstream.request(self.command, self.path, self.rfile.read(size) if size else None, headers)
            response = upstream.getresponse()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in {"connection", "date", "server", "transfer-encoding"}:
                    self.send_header(key, value)
            self.end_headers()
            shutil.copyfileobj(response, self.wfile)
        finally:
            upstream.close()


if __name__ == "__main__":
    port, backend_port = (int(value) for value in sys.argv[1:3])
    with ThreadingHTTPServer(("127.0.0.1", port), Handler) as server:
        server.backend_port = backend_port
        server.storage = Path(sys.argv[3])
        server.writes = threading.Lock()
        server.serve_forever()
