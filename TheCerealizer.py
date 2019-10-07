#!/usr/bin/env python

import argparse
import base64
import gzip
import httplib
import json
import os
import re
import select
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib
import urlparse
import zlib
import requests
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from HTMLParser import HTMLParser
from cStringIO import StringIO
from socketserver import ThreadingMixIn
from subprocess import Popen, PIPE

# SSL VERIFICATION DISABLED
requests.packages.urllib3.disable_warnings()
_verbose = 0


def setup_tls():
    commands = ['openssl genrsa -out ca.key 2048',
                'openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=proxy2 CA"',
                'openssl genrsa -out cert.key 2048',
                'mkdir certs/']
    try:
        for cmd in commands:
            os.system(cmd)
    except Exception as e:
        dbg("Failed to set up TLS configuration")
        os._exit(1)


def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)


def join_with_script_dir(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET
    daemon_threads = True

    def handle_error(self, request, client_address):
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = join_with_script_dir('ca.key')
    cacert = join_with_script_dir('ca.crt')
    certkey = join_with_script_dir('cert.key')
    certdir = join_with_script_dir('certs/')
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(
                self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)

        with self.lock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey,
                            "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        if self.path == 'http://proxy2.test/':
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None and len(req_body_modified) > 0:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
                self.response_handler(req, req_body, res, '')
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(res)
                with self.lock:
                    self.save_handler(req, req_body, res, '')
                return

            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            pass

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        hop_by_hop = (
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding',
        'upgrade')
        for k in hop_by_hop:
            del headers[k]

        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        global _match
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)
        u = urlparse.urlsplit(req.path)
        if req_body is not None:
            if _verb > 1:
                info("Received POST request:\n\n%s\r\n\r\n%s\n\033[0m" % (req_header_text, repr(req_body)))
            if re.match(b'^\xac\xed.*', req_body) or re.match(r'^rO0AB.*', req_body):
                info("Intercepted serialized data request for URI: \n\n%s" % req.path)
                h = req.headers.__str__()
                p = 'POST ' + u.path + "?" + u.query + ' HTTP/1.1\r\n'
                whole = p + h + "\r\n\r\n" + req_body
                if re.search(_match, req_body):
                    a = raw_input("Do you want to mangle it? (y/n): ")
                    if a.lower() == 'y':
                        run(whole, _caddr, _cport)

        if _verb > 2:
            print with_color(36, res_header_text)

        cookies = res.headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            if _verb > 2:
                print with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies)

        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    if _verb > 2:
                        print with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body:
                if _verb > 2:
                    print with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text)

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        self.print_info(req, req_body, res, res_body)


def run_proxy(caddr, cport, addr, port, verbose, HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer,
              protocol="HTTP/1.1"):
    global _verb
    global _caddr
    global _cport
    _caddr = caddr
    _cport = cport
    _verb = verbose
    info("Interceptor proxy listening on %s:%s" % (addr, port))
    server_address = (addr, port)
    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)
    httpd.serve_forever()


def get_len(a):
    return "Length - " + str(len(a)) + " - " + "0x00 " + str(hex(len(a)).split("x")[1].zfill(2))


def get_hex(a):
    b = ""
    for i in a:
        b += str(i.encode("hex"))
    return "Value - " + str(a) + " - " + "0x" + str(b)


def get_params(ascii_data):
    datalines = ascii_data.split("\n")
    params = {}
    for i in range(0, len(datalines)):
        if (re.match(r'.*Value - .* - 0x.*', datalines[i]) and '(object)' in datalines[i - 4]):
            param = str(datalines[i - 5]).strip() + "-" + str(i)
            value = ''.join(re.findall(r'Value - (.*?) -', datalines[i])) 
            params.update({param: value.replace('*', '')})
    return params


def modify_param(ascii_data, param_name, param_value):
    line_index = int(param_name.split("-")[1])
    datalines = ascii_data.split("\n")
    datacopy = list(datalines)
    datacopy[line_index] = re.sub('Value - .+', get_hex(param_value), datalines[line_index])
    datacopy[line_index - 1] = re.sub('Length - .+', get_len(param_value), datalines[line_index - 1])
    return "\n".join(datacopy)


def serial_to_ascii(serialized_data):
    env = dict(os.environ)
    tmp = tempfile.NamedTemporaryFile()
    tmp.write(serialized_data)
    tmp.seek(0)
    if _verbose > 2:
        info("Serialized data from request file: %s" % repr(serialized_data))
    sdump = Popen(['/usr/bin/java', '-jar', './SerializationDumper-v1.1.jar', '-r', tmp.name], stdout=PIPE, shell=False,
                  env=env, bufsize=0)
    ascii_data, err = sdump.communicate()
    if sdump.returncode != 0:
        dbg(
            "SerializationDumper (serial2ascii) exited with error code: %d \nNot great, not terrible." % sdump.returncode)
    tmp.close()
    return ascii_data


def ascii_to_serial(ascii_data):
    env = dict(os.environ)
    tmp = tempfile.NamedTemporaryFile()
    tmp2 = tempfile.NamedTemporaryFile()
    tmp.write(ascii_data)
    tmp.seek(0)
    if _verbose > 2:
        info("ASCII representation of serialized object: \n\n%s\n\n" % ascii_data)
    sdump = Popen(['/usr/bin/java', '-jar', './SerializationDumper-v1.1.jar', '-b', tmp.name, tmp2.name], stdout=PIPE,
                  shell=False, env=env, bufsize=0)
    out, err = sdump.communicate()
    tmp2.seek(0)
    with open(tmp2.name, "rb") as f:
        serial_data = tmp2.read()
    if sdump.returncode != 0:
        dbg("SerializationDumper (ascii2serial) exited with error code: %d \nNot great, not terrible." % (
            sdump.returncode))
    tmp.close()
    tmp2.close()
    with open("last_payload.bin", "wb") as f:
        f.write(serial_data)
    return serial_data


def simple_parser(raw_req_data):
    try:
        parsed_data = {}
        raw_headers = raw_req_data.split("\r\n\r\n")[0]
        parsed_data.update({"raw_headers": raw_req_data.split("\r\n\r\n")[0]})
        post_data = "\r\n\r\n".join(raw_req_data.split("\r\n\r\n")[1:])
        if re.match(r'^rO0AB.*', post_data):
            post_data = base64.b64decode(post_data)
            _isbase64 = True
        data = raw_req_data.split("\n")
        parsed_data.update({"post_data": post_data})
        for line in data:
            if re.match("Host:.*", line, re.IGNORECASE):
                parsed_data.update({"host_header": line.split(':')[1].strip()})
            if re.match("POST /.*", line):
                parsed_data.update({"uri": line.split(' ')[1]})
        parsed_data.update({"url": "http://" + parsed_data["host_header"] + parsed_data["uri"]})
        headers_list = {}
        for h in raw_headers.split("\n"):
            if re.match(r'^([\w-]+): (.*)', h) and not re.match('.*Content-Length.*', h, re.IGNORECASE):
                headers_list.update({h.split(':')[0]: h.split(': ')[1].strip()})
        parsed_data.update({"headers": headers_list})
        return parsed_data
    except Exception as e:
        dbg("Fatal HTTP parser error! ( %s )\nlast input data: %s " % (e, repr(raw_req_data)))
        raise

def replay(parsed_data, params, addr, port):
    global _proxies
    try:
        info("Replaying request to proxy at %s" % _proxies["http"])
        r = requests.post("http://"+str(addr) + ":" + str(port) + parsed_data["uri"],
            headers=parsed_data["headers"], data=urllib.urlencode(params),
            proxies=_proxies, timeout=1)
    except Exception:
        pass


def prepare_curl(parsed_data, params, addr, port):
    string_builder = "curl "
    string_builder += "\"http://" + str(addr) + ":" + str(port) + parsed_data["uri"] + "\" "
    for h in parsed_data["headers"]:
        string_builder += "-H \"" + h.replace("\r", "") + ": " + parsed_data["headers"][h] + "\" "
    string_builder += "-d \"" + urllib.urlencode(params) + "\" "
    return string_builder


def common_data(list1, list2):
    result = False
    for x in list1:
        for y in list2:
            if x == y:
                result = True
                return result
    return result


def dbg(msg):
    if _verbose > 0:
        print  >> sys.stderr, "\n\033[31m[!]\033[0m %s\n" % msg


def info(msg):
    print  "\033[34m[i]\033[0m %s\n" % msg


class S(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        try:
            if _verbose > 1:
                info("REQ: %s [%s] %s %s\n" %
                     (self.address_string(),
                      self.log_date_time_string(),
                      self.headers['Content-Length'],
                      format % args))
        except Exception as e:
            print "Err: %s" % e
            pass

    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

    def _html(self, message):
        m = ''.join([i if ord(i) < 128 else ' ' for i in message])
        m = re.sub("(=|~|\n)", "\r\n", m)
        m = os.linesep.join([s for s in m.splitlines() if len(s) > 6])
        content = "<html><body><head><title>Cerealizer Proxy</title></head><pre>" + m.encode(
            "utf8") + "</pre></body></html>"
        return content

    def do_GET(self):
        self.send_response(405)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(self._html("Method Not Allowed"))

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        try:
            local_ascii = _ascii_data
            parsed_params = {}
            content_length = int(self.headers['Content-Length'])
            content_type = self.headers['Content-Type']
            req_received = self.rfile.read(content_length)
            parsed_params = dict(urlparse.parse_qsl(req_received))
            if not common_data(parsed_params, _params):
                dbg("ERRPR: HTTP Request does not match the parsed file.")
            for p in parsed_params:
                if p in _params:
                    if parsed_params[p] != _params[p]:
                        info("Received modified payload: \n\n%s" % parsed_params[p])
                        local_ascii = modify_param(local_ascii, p, parsed_params[p])
                        local_serial = ascii_to_serial(local_ascii)
                        if _isbase64:
                            local_serial = base64.b64encode(local_serial)
                        try:
                            r = requests.post(url=_parsed_data["url"], headers=_parsed_data["headers"],
                                              data=local_serial, timeout=10)
                        except Exception:
                            r = requests.post(url=_parsed_data["url"].replace("http", "https"),
                                              headers=_parsed_data["headers"], data=local_serial, verify=False, timeout=10)
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(self._html("Bad request"))
            dbg("HTTP Request fatal error: %s" % e)
            pass
        try:
            if r in locals():
                self.send_response(r.status_code)
            else:
                self.send_response(400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(self._html(r.text))
        except NameError as e:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(self._html("Query parameters left unchanged!"))
            dbg("Received an unmodified or malformed HTTP query: %s" % e)
            pass


class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass


def run(request_data, addr, port, server_class=ThreadingSimpleServer, handler_class=S):
    global _ascii_data
    global _parsed_data
    global _params
    global _isbase64
    global _verbose
    global _proxies
    _isbase64 = False
    if re.match(r'^rO0AB.*', request_data):
        request_data = base64.b64decode(request_data)
        print request_data
        _isbase64 = True
    _parsed_data = simple_parser(request_data)
    _ascii_data = serial_to_ascii(_parsed_data["post_data"])
    _params = get_params(_ascii_data)
    print "\n\033[32m[+] Request file successfully parsed\n"
    print "[+] URL encoded proxy server running on port %s:%s\n" % (addr, port)
    if len(_proxies) > 0:
        replay(_parsed_data, _params, addr, port)
    info("Example proxy usage (curl):")
    info(prepare_curl(_parsed_data, _params, addr, port))

    server_address = (addr, port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TheCerealizer: Proxy for automated scans of serialized java")
    parser.add_argument(
        "-l",
        "--listen",
        default="localhost",
        help="Specify the IP address on which the cerealizer server listens",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=10000,
        help="Specify the port on which the cerealizer server listens",
    )
    parser.add_argument(
        "-i",
        "--intercept",
        default="localhost",
        help="Specify the IP address on which the interceptor proxy listens",
    )
    parser.add_argument(
        "-s",
        "--iport",
        type=int,
        default=10001,
        help="Specify the port on which the interceptor server listens",
    )
    parser.add_argument(
        "-f",
        "--file",
        help="Specify the file which contains HTTP request with serialized object",
    )
    parser.add_argument(
        "-r",
        "--replay",
        help="Specify the proxy server for replay of the request (i.e. ZAP, Burp) syntax: 127.0.0.1:8080",
    )
    parser.add_argument(
        "-m",
        "--match",
        default='.*',
        help="Specify the regex to filter out intercepted requests",
    ) 
    parser.add_argument(
        "-v",
        "--verbose",
        action='count',
        default=0,
        help="Enable verbose output",
    )
    args = parser.parse_args()
    try:
        print "\n" + zlib.decompress(base64.b64decode("eJy1kEEOw"
                                                      "jAMBO98IRffKBKSW5XfJNL2A/mBH4/XCaighgvgqLa72Uzcpnxbasrr"
                                                      "XOUHkfJcT+kVCYZgb6NwEG+uIVLjeBGLGjD1Uto9TJRYTSZcgMcI/dq"
                                                      "jKZ2gReUM5zpMvFdpnYvoEjYxLuy2bIQMgvUlZGi42T2lCd0R7rY1/p"
                                                      "c+giN5BMbP5QNlpijReLryFdoNhk/IL+NfyDt6F4gO"))
        _verbose = args.verbose
        _proxies = {}
        _match = args.match
        if args.replay:
            _proxies = {"http":args.replay,"https":args.replay}
        if not os.path.isfile("SerializationDumper-v1.1.jar"):
            parser.error("\nSerializationDumper-v1.1.jar <--- file not found")
        if args.file:
            with open(args.file, "rb") as f:
                request_data = f.read()
            run(request_data, args.listen, args.port)
        else:
            cert_files = ["ca.crt", "ca.key", "cert.key"]
            cert_exist = [f for f in cert_files if os.path.isfile(f)]
            cert_non_exist = list(set(cert_exist) ^ set(cert_files))
            if len(cert_non_exist) > 0:
                setup_tls()
            run_proxy(args.listen, args.port, args.intercept, args.iport, _verbose)
    except KeyboardInterrupt:
        os._exit(1)
    except Exception as e:
        _verbose = 1
        dbg("Fatal error: %s" % e)
        sys.exit(1)
