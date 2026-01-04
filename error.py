import ssl, socket

ctx = ssl.create_default_context()
s = socket.create_connection(("google.com", 443))
tls = ctx.wrap_socket(s, server_hostname="google.com")
print(tls.version())
