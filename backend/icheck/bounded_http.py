"""Bound non-streaming urllib responses by elapsed time, not keep-alive activity."""
from __future__ import annotations

import socket
import threading
import time


def read_bounded_response(opener, request, *, timeout: float, max_bytes: int) -> bytes:
    deadline = time.monotonic() + timeout
    with opener.open(request, timeout=timeout) as response:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Model response elapsed-time limit exceeded")
        # urllib exposes the stdlib HTTPResponse socket here. shutdown interrupts
        # even a partial chunk / read(size) kept alive by periodic provider bytes.
        transport = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
        expired = threading.Event()

        def abort():
            expired.set()
            if transport is not None:
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        timer = threading.Timer(remaining, abort)
        timer.daemon = True
        timer.start()
        try:
            reader = getattr(response, "read1", None)
            if reader is None:  # Injected test transports / bounded in-memory data.
                body = response.read(max_bytes + 1)
            else:
                chunks, size = [], 0
                while size <= max_bytes:
                    if expired.is_set() or time.monotonic() >= deadline:
                        raise TimeoutError("Model response elapsed-time limit exceeded")
                    chunk = reader(min(8192, max_bytes + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                body = b"".join(chunks)
        except Exception:
            if expired.is_set():
                raise TimeoutError("Model response elapsed-time limit exceeded") from None
            raise
        finally:
            timer.cancel()
        if expired.is_set() or time.monotonic() >= deadline:
            raise TimeoutError("Model response elapsed-time limit exceeded")
        return body
