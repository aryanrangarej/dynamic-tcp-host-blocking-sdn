#!/usr/bin/env python3
"""
Low-Level Concurrent TCP Socket Application Server
Team 10 - UE25CS243A Computer Networks Mini-Project

Implements a multi-threaded TCP server using Python's standard `socket` module.
Fulfills Unit 2 socket programming requirements and acts as the target service on h4.
"""

import socket
import threading
import argparse
import sys
import time
import config


class TCPServer:
    def __init__(self, host=config.SERVER_IP, port=config.SERVER_PORT):
        self.host = host
        self.port = port
        self.running = False
        self.total_connections = 0
        self.lock = threading.Lock()

    def handle_client(self, conn, client_addr):
        """
        Worker thread for an accepted client connection.
        Performs application data exchange and handles socket timeout/closure.
        """
        conn.settimeout(5.0)
        with conn:
            try:
                data = conn.recv(1024)
                if data:
                    message = data.decode('utf-8', errors='ignore').strip()
                    # Application-level response protocol
                    response = f"ACK: Received '{message}' from {client_addr[0]}\n".encode('utf-8')
                    conn.sendall(response)
            except socket.timeout:
                pass
            except OSError:
                pass

    def start(self):
        """Initializes and runs the TCP listening socket."""
        self.running = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            # Allow immediate reuse of the port after termination
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen(128)
            print(f"[SERVER] TCP Application Server active on {self.host}:{self.port}")
            print(f"[SERVER] Listening for incoming client connections (Multi-threaded)...")

            try:
                while self.running:
                    conn, addr = server_sock.accept()
                    with self.lock:
                        self.total_connections += 1
                        current_total = self.total_connections

                    # Dispatch request to daemon thread to maintain non-blocking server
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr),
                        daemon=True
                    )
                    client_thread.start()
            except KeyboardInterrupt:
                print("\n[SERVER] Shutting down TCP Server...")
            finally:
                self.running = False


def main():
    parser = argparse.ArgumentParser(description="Multi-threaded Low-Level TCP Socket Server")
    parser.add_argument("--host", default=config.SERVER_IP, help=f"Binding IP (default: {config.SERVER_IP})")
    parser.add_argument("--port", type=int, default=config.SERVER_PORT, help=f"Binding Port (default: {config.SERVER_PORT})")
    args = parser.parse_args()

    server = TCPServer(host=args.host, port=args.port)
    server.start()


if __name__ == "__main__":
    main()
