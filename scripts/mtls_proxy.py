#!/usr/bin/env python3
"""
mTLS TCP Proxy: forwards plain TCP (MongoDB Compass) to Envoy with mTLS.

Usage:
    python scripts/mtls_proxy.py

Then connect MongoDB Compass to: mongodb://root:example@localhost:27018/
"""

import socket
import ssl
import sys
import threading
from pathlib import Path

CERT = Path(__file__).resolve().parent.parent / "certs" / "client" / "mattia.mandorlini.crt"
KEY = Path(__file__).resolve().parent.parent / "certs" / "client" / "mattia.mandorlini.key"
CA = Path(__file__).resolve().parent.parent / "volumes" / "certs" / "ca" / "ca.crt"
ENVOY_HOST = "localhost"
ENVOY_PORT = 10000
LOCAL_PORT = 27018
BUFFER_SIZE = 65536


def pipe(src, dst, name=""):
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            src.close()
        except:
            pass
        try:
            dst.close()
        except:
            pass


def handle_client(client_sock, addr):
    print(f"[+] Connection from {addr}")
    try:
        ctx = ssl.create_default_context(cafile=str(CA))
        ctx.load_cert_chain(str(CERT), str(KEY))
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        envoy = socket.create_connection((ENVOY_HOST, ENVOY_PORT), timeout=10)
        tls = ctx.wrap_socket(envoy, server_hostname=ENVOY_HOST)
        print(f"    mTLS to Envoy established (cipher: {tls.cipher()[0]})")

        t1 = threading.Thread(target=pipe, args=(client_sock, tls, "C->E"), daemon=True)
        t2 = threading.Thread(target=pipe, args=(tls, client_sock, "E->C"), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception as e:
        print(f"    Error: {e}")
    finally:
        try:
            client_sock.close()
        except:
            pass
    print(f"[-] Connection closed from {addr}")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LOCAL_PORT))
    srv.listen(10)
    print(f"[*] mTLS Proxy listening on :{LOCAL_PORT}")
    print(f"    Forwarding to Envoy mTLS {ENVOY_HOST}:{ENVOY_PORT}")
    print(f"    Client cert: {CERT}")
    print(f"    Connect Compass to: mongodb://zta_user:zta_password@localhost:{LOCAL_PORT}/")
    print("")
    try:
        while True:
            client, addr = srv.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
