# TheCerealizer

Yet another serialized object converter tool.
Just because it was easier to write one than to set up BurpJDSer.

This proxy is based on awsome [SerializationDumper](https://github.com/NickstaDB/SerializationDumper) tool by NikstaDB
and heavly modified version of [proxy2](https://github.com/futuresimple/proxy2) script by futuresimple.

#### Main features
* Convert serialized object stream to url encoded form and back
* Read serialized objects from HTTP requests file
* Intercept HTTP requests through proxy
* Forward converted objects to HTTP proxy for further processing, (i.e. Burp, OWASP ZAP)
* Create basic curl syntax for easy integration with other tools like SQLMap
* Read base64 wrapped serialized data
* Filter intercepted requests with regex pattern
* No source or Java configuration needed!

#### Limitations
* Accepts only serialized "full-body" HTTP POST requests
* Strictly dependant on SerializationDumper capabilities
* Parses only `String` attributes of a class
* Works only on one request at a time (multiprocessing in future releases)
* Bugs

#### Usage examples
* Reading request from file and replaying it to Burp:

`./TheCerealizer.py -f http_request.raw -r 127.0.0.1:8080 -vv`

* Starting a intercept proxy on port 9999, filter requests with regex and replay it to Burp:

`./TheCerealizer.py -s 9999 -m '.*current_user_id.*' -r 127.0.0.1:8080 -v`

#### Example output

```
root@null [11:51:54 PM] [/opt/TheCerealizer/]
⚡ python TheCerealizer.py -s 1111 -r 127.0.0.1:8081 -vv 

                                                                    
     _____ _            ___                    _ _                  
    /__   \ |__   ___  / __\___ _ __ ___  __ _| (_)_______ _ __     
      / /\/ '_ \ / _ \/ /  / _ \ '__/ _ \/ _` | | |_  / _ \ '__|    
     / /  | | | |  __/ /__|  __/ | |  __/ (_| | | |/ /  __/ |       
     \/   |_| |_|\___\____/\___|_|  \___|\__,_|_|_/___\___|_|       
                                                                    
                                                                    

[i] Interceptor proxy listening on localhost:1111

[i] Received POST request:

POST http://127.0.0.1/someapp/remoting/Route HTTP/1.1
Content-Type: application/x-java-serialized-object
Content-Length: 289
User-Agent: Java/1.6.0_21
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Cookie: SOMECOOKIE=VALUE
Host: 127.0.0.1
Accept-Encoding: gzip, deflate


'\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x01sr\x00\x0cjava.net.URL\x96%76\x1a\xfc\xe4r\x03\x00\x07I\x00\x08hashCodeI\x00\x04portL\x00\tauthorityt\x00\x12Ljava/lang/String;L\x00\x04fileq\x00~\x00\x03L\x00\x04hostq\x00~\x00\x03L\x00\x08protocolq\x00~\x00\x03L\x00\x03refq\x00~\x00\x03xp\xff\xff\xff\xff\xff\xff\xff\xfft\x00\x0bexample.comt\x00\x08/exampleq\x00~\x00\x05t\x00\x04httppxt\x00\x1ahttp://example.com/examplex'


[i] Intercepted serialized data request for URI: 

http://127.0.0.1/someapp/remoting/Route

Do you want to mangle it? (y/n): y

[+] Request file successfully parsed

[+] URL encoded proxy server running on port localhost:10000

[i] Replaying request to proxy at 127.0.0.1:8081

[i] Example proxy usage (curl):

[i] curl "http://localhost:10000/someapp/remoting/Route?" -H "Host: 127.0.0.1" -H "Cookie: SOMECOOKIE=VALUE" -H "Accept-Encoding: gzip, deflate" -H "Content-Type: application/x-java-serialized-object" -H "Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2" -H "User-Agent: Java/1.6.0_21" -d "authority-119=example.com&file-125=%2Fexample&protocol-135=http" 

[i] Received modified payload: 

evil.com

[i] Received modified payload: 

/shell.jsp

[i] REQ: localhost [07/Oct/2019 23:53:24] 62 "POST /someapp/remoting/Route? HTTP/1.1" 500 -


```

#### Options

```
usage: TheCerealizer.py [-h] [-l LISTEN] [-p PORT] [-i INTERCEPT] [-s IPORT]
                        [-f FILE] [-r REPLAY] [-m MATCH] [-v]

TheCerealizer: Proxy for automated scans of serialized java

optional arguments:
  -h, --help            show this help message and exit
  -l LISTEN, --listen LISTEN
                        Specify the IP address on which the cerealizer server
                        listens
  -p PORT, --port PORT  Specify the port on which the cerealizer server
                        listens
  -i INTERCEPT, --intercept INTERCEPT
                        Specify the IP address on which the interceptor proxy
                        listens
  -s IPORT, --iport IPORT
                        Specify the port on which the interceptor server
                        listens
  -f FILE, --file FILE  Specify the file which contains HTTP request with
                        serialized object
  -r REPLAY, --replay REPLAY
                        Specify the proxy server for replay of the request
                        (i.e. ZAP, Burp) syntax: 127.0.0.1:8080
  -m MATCH, --match MATCH
                        Specify the regex to filter out intercepted requests
  -v, --verbose         Enable verbose output
```

###### Disclaimer
> _This tool will create multiple files in your current directory:_
> _**ca.crt**, **ca.key**, **cert.key** and **certs/** directory for TLS proxy_
> and _**last_payload.bin** containing last generated payload in raw form_
