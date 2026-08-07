#!/usr/bin/env python3
import http.server
import pathlib
import sys


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        pass


root = pathlib.Path(sys.argv[1]).resolve(strict=True)
server = http.server.ThreadingHTTPServer(
    ("127.0.0.1", 0),
    lambda *args, **kwargs: QuietHandler(*args, directory=str(root), **kwargs),
)
print(server.server_port, flush=True)
server.serve_forever()
