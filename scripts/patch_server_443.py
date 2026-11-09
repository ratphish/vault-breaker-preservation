path = r'D:\vault-breaker-preservation\scripts\marathon_server.py'
with open(path, 'r', encoding='utf-8') as f:
    code = f.read()

# Let's add a thread for port 443 in main()
target = """    plain_thread = threading.Thread(target=start_plaintext_http, args=(server, 8081), daemon=True)
    plain_thread.start()"""

replacement = """    plain_thread = threading.Thread(target=start_plaintext_http, args=(server, 8081), daemon=True)
    plain_thread.start()

    def start_https_443(server, cert_path, key_path):
        try:
            httpd_443 = ThreadedHTTPServer(("0.0.0.0", 443), SignOnHTTPHandler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            httpd_443.socket = ctx.wrap_socket(httpd_443.socket, server_side=True)
            server_log("[*] HTTPS SignOn service active with TLS on https://127.0.0.1:443 (Port 443)")
            httpd_443.serve_forever()
        except Exception as e:
            server_log(f"[-] Port 443 HTTPS bind warning: {e}")"""

code = code.replace(target, replacement, 1)

# Now launch the thread if certs exist
target_launch = """    if cert_path and key_path:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        server_log(f"[*] HTTPS SignOn service active with TLS on https://127.0.0.1:{server.http_port} (Cert: {cert_path})")"""

replacement_launch = """    if cert_path and key_path:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        server_log(f"[*] HTTPS SignOn service active with TLS on https://127.0.0.1:{server.http_port} (Cert: {cert_path})")
        threading.Thread(target=start_https_443, args=(server, cert_path, key_path), daemon=True).start()"""

code = code.replace(target_launch, replacement_launch, 1)

with open(path, 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(code)

print("[+] Successfully added Port 443 HTTPS listener to marathon_server.py!")
