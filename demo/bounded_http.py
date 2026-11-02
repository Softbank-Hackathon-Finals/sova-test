"""Finite loopback qualification HTTP resources; not a public ASGI server."""

from http.server import ThreadingHTTPServer
import threading


class BoundedLoopbackServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, handler, *, max_connections=16, read_timeout=3):
        if (
            address[0] != "127.0.0.1"
            or type(max_connections) is not int
            or not 1 <= max_connections <= 64
            or not 0 < read_timeout <= 5
        ):
            raise ValueError("Bounded loopback server configuration required")
        self._slots = threading.BoundedSemaphore(max_connections)
        self.read_timeout = read_timeout
        super().__init__(address, handler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(self.read_timeout)
        return request, address

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n"
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()
