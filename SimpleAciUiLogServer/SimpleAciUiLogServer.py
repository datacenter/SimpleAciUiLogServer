#!/usr/bin/env python
"""
A Simple HTTP server that accepts POSTs from the APIC UI as a remote API
Inspector.

Written by Mike Timm (mtimm@cisco.com)
Based on code written by Fredrik Lundh & Brian Quinlan.
"""

import os
import BaseHTTPServer
from StringIO import StringIO
import SocketServer
import socket
import select
import cgi
import ssl
import re
import logging
import json
import tempfile
from argparse import ArgumentParser
from pkg_resources import resource_string

try:
    import fcntl
except ImportError:
    fcntl = None

server_cert = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC+oA+hYsF3uBIMt7i1ELfUFnyf4/MKM/Ylmy4yBc0/YhqANXYk
so3+gAGkgRlv9ODdsFS7KvjzyaT0kjgA3ahDPyvtroAOWsdFdHJvtS4Ek1WI1Bee
0hNZlTmjQgnjp9ENYl9ImGWghcubJhtse5cJhL9c/hq40do4llZjaaEiCQIDAQAB
AoGAYbd1K7qPCErAXeqT8aVXRo4cZm4YeSN3y4FH5faZZyNoCE7feCJbrZl6vhQ7
sOtrldi9JpD5uyaju4d00+TMSoFqnTuAYLg4CEUAkAq2Hgg1EfQfPpC8IgYdR5qQ
hRu0JArXldch1YLHw8GQGkkZe/cJXiHs/FPjmdUQSsydI50CQQDuEecLrSLjuMpE
i8xjD9cQxSDTHJFDZttVb08fjaKFJk993TsUR2t/eR92OR5m0CFei/RUyYpUaPbk
1s3Eau7XAkEAzPtnMMKoGR3qfLqXzfmgLwQA0UbeV8PbxRCkaCnSYcpn0qJH7UtS
Qjb4X6MPA9bNUnydWFgbPgz4MwKRo0q6HwJAP6DxS6GerZZ6GQ/0NJXLOWQ2fbYo
7QbUoGT7lMdaJJQ0ssMqQyVDifJpgkOJ6JjAEnD9gJvNKPpU4py2qkSaSQJANngr
0Jo5XwtDD0fqJPLLbRLsQLBLTxkdoj0s4v0SCahmdGNpJ5ZXUn8W+xryV3vR7bRt
f1dSTefWYH+zQagO0wJBANlNp79CN7ylgXdrhRVQmBsXHN4G8biUUxMYsfK4Ao/i
Ga3xtkYLv7OmrtY+Gx6w56Jqxyucaka8VBHK0/7JTLE=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIID+jCCA2OgAwIBAgIJALUh5RwHQhJoMA0GCSqGSIb3DQEBBQUAMIGvMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExETAPBgNVBAcTCFNhbiBKb3NlMRUwEwYDVQQK
EwxhcGlpbnNwZWN0b3IxHTAbBgNVBAsTFFNpbXBsZUFjaVVpTG9nU2VydmVyMSow
KAYDVQQDEyFTaW1wbGVBY2lVaUxvZ1NlcnZlci5hcGlpbnNwZWN0b3IxHjAcBgkq
hkiG9w0BCQEWD210aW1tQGNpc2NvLmNvbTAgFw0xNTAxMjMwMDI1NDJaGA8zMDE0
MDUyNjAwMjU0Mlowga8xCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTERMA8GA1UE
BxMIU2FuIEpvc2UxFTATBgNVBAoTDGFwaWluc3BlY3RvcjEdMBsGA1UECxMUU2lt
cGxlQWNpVWlMb2dTZXJ2ZXIxKjAoBgNVBAMTIVNpbXBsZUFjaVVpTG9nU2VydmVy
LmFwaWluc3BlY3RvcjEeMBwGCSqGSIb3DQEJARYPbXRpbW1AY2lzY28uY29tMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+oA+hYsF3uBIMt7i1ELfUFnyf4/MK
M/Ylmy4yBc0/YhqANXYkso3+gAGkgRlv9ODdsFS7KvjzyaT0kjgA3ahDPyvtroAO
WsdFdHJvtS4Ek1WI1Bee0hNZlTmjQgnjp9ENYl9ImGWghcubJhtse5cJhL9c/hq4
0do4llZjaaEiCQIDAQABo4IBGDCCARQwHQYDVR0OBBYEFN2EqumA49KSEPjLLSni
UtKth4zQMIHkBgNVHSMEgdwwgdmAFN2EqumA49KSEPjLLSniUtKth4zQoYG1pIGy
MIGvMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExETAPBgNVBAcTCFNhbiBKb3Nl
MRUwEwYDVQQKEwxhcGlpbnNwZWN0b3IxHTAbBgNVBAsTFFNpbXBsZUFjaVVpTG9n
U2VydmVyMSowKAYDVQQDEyFTaW1wbGVBY2lVaUxvZ1NlcnZlci5hcGlpbnNwZWN0
b3IxHjAcBgkqhkiG9w0BCQEWD210aW1tQGNpc2NvLmNvbYIJALUh5RwHQhJoMAwG
A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEABPx5cxBNOjWOxZbiRVfpzKac
MKs4tFNtEmilAY7kvNouGaSl1Yw2fCpGXjstOG0+SxPy34YgeQSVOGQI1KXhd7vk
nALqxrKiP2rzpZveBkjq5voRpFw2creEXyt76EKQgwRHYJP60Vu3bYnYNoFHdUwE
TOBaHjC6ZZLRd77dd3s=
-----END CERTIFICATE-----
"""

class SimpleLogDispatcher(object):

    # map log4javascript logging levels to python logging levels
    loglevel = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARN': logging.WARNING,
        'ERROR': logging.ERROR,
        'FATAL': logging.CRITICAL
    }

    indent = 4
    prettyprint = False
    strip_imdata = False

    def __init__(self, allow_none=False):
        self.funcs = {}
        self.instance = None
        self.allow_none = allow_none

    def register_instance(self, instance):
        self.instance = instance

    def register_function(self, function, name=None):
        """Registers a function to respond to Log requests.

        The optional name argument can be used to set a Unicode name
        for the function.
        """
        if name is None:
            name = function.__name__
        self.funcs[name] = function


    def _dispatch(self, method, params):
        method = method.replace(" ", "")
        func = None
        try:
            # check to see if a matching function has been registered
            func = self.funcs[method]
        except KeyError:
            if self.instance is not None:
                # check for a _dispatch method
                if hasattr(self.instance, '_dispatch'):
                    return self.instance._dispatch(method, params)
                else:
                    func = method

        if func is not None:
            return func(**params)
        else:
            # Log some default things if no functions are registered.
            datastring = ""
            paramkeys = params.keys()
            if 'data' in paramkeys:
                try:
                    preamble = params['data']['preamble']
                    level = self.loglevel[preamble.split(" ")[1]]
                except KeyError:
                    level = logging.DEBUG
                try:
                    datastring += "\n    method: {0}\n".format(
                        params['data']['method'])
                except KeyError:
                    datastring += "\n    method: None\n"
                try:
                    datastring += "       url: {0}\n".format(
                        params['data']['url'])
                except KeyError:
                    if params['data']['method'] == "Event Channel Message":
                        datastring += "       url: N/A\n"
                    else:
                        datastring += "       url: None\n"
                try:
                    jstring = params['data']['payload']
                    if self.prettyprint:
                        jstring = json.dumps(json.loads(jstring),
                                                        indent=self.indent)
                    datastring += "   payload: {0}\n".format(jstring)
                except KeyError:
                    if params['data']['method'] == "Event Channel Message":
                        datastring += "   payload: N/A\n"
                    else:
                        datastring += "   payload: None\n"
                try:
                    jstring =  params['data']['response']
                    jdict = json.loads(jstring)
                    try:
                        totalCount = jdict['totalCount']
                    except:
                        # bug!
                        totalCount = '0'
                    datastring += "    # objs: {0}\n".format(totalCount)
                    if self.prettyprint:
                        if self.strip_imdata:
                            jstring = json.dumps(jdict['im_data'],
                                                 indent=self.indent)
                        else:
                            jstring =  json.dumps(jdict, indent = self.indent)
                    datastring += "  response: {0}\n".format(jstring)
                except KeyError:
                    datastring += "  response: None\n"
            logging.log(level, datastring)
            return datastring


class SimpleLogRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    @property
    def log_paths(self):
        return self._log_paths

    @log_paths.setter
    def log_paths(self, value):
        self._log_paths = value

    def is_log_path_valid(self):
        if self.log_paths:
            return self.path in self.log_paths
        else:
            # If .log_paths is empty, just assume all paths are legal
            return True

    def send_200_resp(self, response):
        self.send_response(200)
        self.send_header("Content-type", "text/text")
        if response is not None:
            resplen = str(len(response))
        else:
            resplen = 0
        self.send_header("Content-length", resplen)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        if response is not None:
            self.wfile.write(response)

    def do_GET(self):
        """Handles the HTTP GET request.

        Simply returns a small amount of info so you can tell the server is
        functioning.
        """
        if not self.is_log_path_valid():
            self.report_404()
            return
        # TODO: Add more info.
        resp = "The server is working."
        self.send_200_resp(resp)
        #self.wfile.write(resp)

    def do_POST(self):
        """Handles the HTTP/S POST request.

        Attempts to interpret all HTTP POST requests as Log calls,
        which are forwarded to the server's _dispatch method for handling.
        """
        if not self.is_log_path_valid():
            self.report_404()
            return

        try:
            # Get arguments by reading body of request.
            # We read this in chunks to avoid straining
            # socket.read(); around the 10 or 15Mb mark, some platforms
            # begin to have problems (bug #792570).
            max_chunk_size = 10 * 1024 * 1024
            size_remaining = int(self.headers["content-length"])
            L = []
            while size_remaining:
                chunk_size = min(size_remaining, max_chunk_size)
                chunk = self.rfile.read(chunk_size)
                if not chunk:
                    break
                L.append(chunk)
                size_remaining -= len(L[-1])
            data = ''.join(L)

            data = self.decode_request_content(StringIO(data))
            if data is None:
                return  # response has been sent

            if 'data' in data.keys() and 'method' in data['data'].keys():
                response = self.server._dispatch(data['data']['method'], data)
            else:
                response = None

        except Exception, e:  # This should only happen if the module is buggy
            # internal error, report as HTTP server error
            self.send_response(500)
            raise
        else:
            # got a valid LOG response
            self.send_200_resp(response)

    @staticmethod
    def extract_form_fields(item):
        # Strip off any trailing \r\n
        formitems = item.value.rstrip('\r\n')
        # Split the items by newline, this gives us a list of either 1, 3, 4
        # or 5 items long
        itemlist = formitems.split("\n")
        # Setup some regular expressions to parse the items
        re_list = [
            re.compile(
                '^[0-1][0-9]:[0-5][0-9]:[0-5][0-9] DEBUG - $'),
            re.compile('^(payload)({".*)$'),
            re.compile('^([a-z]+): (.*)$'),
        ]
        itemdict = {}
        # Go through the 1, 3, 4 or 5 items list
        for anitem in itemlist:
            # Compare each item to the regular expressions
            for a_re in re_list:
                match = re.search(a_re, anitem)
                if match:
                    if len(match.groups()) == 0:
                        # We have a match but no groups, must be
                        # the preamble.
                        itemdict['preamble'] = match.group(0)
                    elif len(match.groups()) == 2:
                        # All other re's should have 2 matches
                        itemdict[match.group(1)] = match.group(2)
                    # We already have a match, skip other regular expressions.
                    continue
        return itemdict


    def decode_request_content(self, datafile):
        content_type = self.headers.get("Content-Type", "notype").lower()
        if content_type == 'application/x-www-form-urlencoded':
            # The data is provided in a urlencoded format.  Unencode it into
            # cgi FieldStorage/MiniFieldStorage objects in a form container
            form = cgi.FieldStorage(
                fp=datafile,
                headers=self.headers,
                environ=dict(REQUEST_METHOD='POST',
                             CONTENT_TYPE=self.headers['Content-Type'],
                )
            )
            itemdict = {}
            for item in form.list:
                if item.name == 'data':
                    itemdict['data'] = \
                        SimpleLogRequestHandler.extract_form_fields(item)
                elif item.name == 'layout':
                    # http://log4javascript.org/docs/manual.html#layouts
                    itemdict['layout'] = item.value
            return itemdict
        else:
            self.send_response(501,
                               "Content-Type %r not supported" % content_type)
        self.send_header("Content-length", "0")
        self.end_headers()
        return None


    def report_404(self):
        # Report a 404 error
        self.send_response(404)
        response = 'No such page'
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


    def log_request(self, code='-', size='-'):
        """Selectively log an accepted request."""
        if self.server.logRequests:
            BaseHTTPServer.BaseHTTPRequestHandler.log_request(self, code, size)


class SimpleAciUiLogServer(SocketServer.TCPServer,
                           SimpleLogDispatcher):

    allow_reuse_address = True
    _send_traceback_header = False


    def __init__(self, addr, cert=None,
                 requestHandler=SimpleLogRequestHandler,
                 logRequests=False, allow_none=False, bind_and_activate=True,
                 location=None):
        self.logRequests = logRequests
        self._cert = cert
        self.daemon = True

        if location is not None:
            if not location.startswith("/"):
                location = "/" + str(location)
            requestHandler.log_paths = [location]

        SimpleLogDispatcher.__init__(self, allow_none)
        SocketServer.TCPServer.__init__(self, addr, requestHandler,
                                        bind_and_activate)

        # [Bug #1222790] If possible, set close-on-exec flag; if a
        # method spawns a subprocess, the subprocess shouldn't have
        # the listening socket open.
        if fcntl is not None and hasattr(fcntl, 'FD_CLOEXEC'):
            flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
            flags |= fcntl.FD_CLOEXEC
            fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)

        if self._cert:
            self.socket = ssl.wrap_socket(self.socket,
                                          certfile=self.cert,
                                          server_side=True)

    @property
    def cert(self):
        '''
        The name of the file containing the server certificate for https
        '''
        return self._cert

    @cert.setter
    def cert(self, value):
        self._cert = value

# Simple dispatch methods.  You can register these and override the default
# behavior of just printing the data out.
#def undefined(**params):
#    logging.debug("Got an undefined, params: {0}".format(params))
#
#
#def GET(**params):
#    #pass #- this would ignore all get's
#    logging.debug("Got a GET, params: {0}".format(params))
#
#
#def POST(**params):
#    logging.debug("Got a POST, params: {0}".format(params))
#
#
#def HEAD(**params):
#    logging.debug("Got a HEAD, params: {0}".format(params))
#
#
#def DELETE(**params):
#    logging.debug("Got a DELETE, params: {0}".format(params))
#
#
#def EventChannelMessage(**params):
#    logging.debug("Got an Event Channel Message, params: {0}".format(params))

# use a threaded server so multiple connections can send data simultaneously
class ThreadingSimpleAciUiLogServer(SocketServer.ThreadingMixIn,
                   SimpleAciUiLogServer):
    '''
    Create a threading SimpleAciUiLogServer so that multiple concurrent
    connections do not block eachother.
    '''
    pass

# purposely not part of ThreadingSimpleAciUiLogServer
def serve_forever(servers, poll_interval=0.5):
    '''
    Handle n number of threading servers, for non-threading servers simply use
    the native server_forever function.
    '''
    while True:
        r, w, e = select.select(servers,[],[],poll_interval)
        for server in servers:
            if server in r:
                server.handle_request()

def main():
    parser = ArgumentParser('Remote APIC API Inspector and GUI Log Server')
    parser.add_argument('-a', '--apicip', help='If you have a multihomed ' +
                                               'system, where the apic is ' +
                                               'on a private network, the ' +
                                               'server will print the ' +
                                               'ip address your local ' +
                                               'system has a route to ' +
                                               '8.8.8.8.  If you want the ' +
                                               'server to print a more ' +
                                               'accurate ip address for ' +
                                               'the server you can tell it ' +
                                               'the apicip address.',
                        required=False, default='8.8.8.8')
    parser.add_argument('-p', '--port', help='Local port to listen on,' +
                                             ' default=8987', default=8987,
                        type=int, required=False)
    parser.add_argument('-s', '--sslport', help='Local port to listen on ' +
                                                ' for ssl connections, ' +
                                                ' default=8443', default=8443,
                        type=int, required=False)
    parser.add_argument('-c', '--cert', help='The server certificate file' +
                                                ' for ssl connections, ' +
                                                ' default="server.pem"',
                        type=str, required=False)
    parser.add_argument('-l', '--location', help='Location that transaction ' +
                                                 'logs are being sent to, ' +
                                                 'default=/apiinspector',
                        default="/apiinspector", required=False)
    parser.add_argument('-r', '--requests-log', help='Log server requests ' +
                                                    'and response codes to ' +
                                                    'standard error',
                        action='store_true', default=False, required=False)
    parser.add_argument('-d', '--delete_imdata', help='Strip the imdata ' +
                                                    'from the response and ' +
                                                    'payload',
                        action='store_true', default=False, required=False)
    parser.add_argument('-n', '--nice-output', help='Pretty print the ' +
                                                    'response and payload',
                        action='store_true', default=False, required=False)
    parser.add_argument('-i', '--indent', help='The number of spaces to ' +
                                                    'indent when pretty ' +
                                                    'printing',
                        type=int, default=2, required=False)
    parser.add_argument('-v', '--verbose', help='Enable debugging',
                        action='store_true', default=False, required=False)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s - \n%(message)s')

    if not args.location.startswith("/"):
        args.location = "/" + str(args.location)

    ThreadingSimpleAciUiLogServer.prettyprint = args.nice_output
    ThreadingSimpleAciUiLogServer.indent = args.indent
    ThreadingSimpleAciUiLogServer.strip_imdata = args.delete_imdata

    # Instantiate a http server
    http_server = ThreadingSimpleAciUiLogServer(("", args.port),
                                       logRequests=args.requests_log,
                                       location=args.location)

    if not args.cert:
        cert_file = tempfile.NamedTemporaryFile(delete=False)
        cert_file.write(server_cert)
        cert_file.close()
        cert = cert_file.name
    else:
        cert = args.cert

    # Instantiate a https server as well
    https_server = ThreadingSimpleAciUiLogServer(("", args.sslport),
                                        cert=cert, location=args.location,
                                        logRequests=args.requests_log)

    if not args.cert:
        os.unlink(cert_file.name)

    # Example of registering a function for a specific method.  The funciton
    # needs to exist of course.  Note:  undefined seems to be the same as
    # POST or EventChannelMessage but the logging facility on the APIC seems
    # to get in a state where instead of setting the method properly it sets it
    # to undefined.
    # These registered functions could then be used to take specific actions or
    # be silent for specific methods.
    #http_server.register_function(GET)
    #http_server.register_function(POST)
    #http_server.register_function(HEAD)
    #http_server.register_function(DELETE)
    #http_server.register_function(undefined)
    #http_server.register_function(EventChannelMessage)

    # This simply sets up a socket for UDP which has a small trick to it.
    # It won't send any packets out that socket, but this will allow us to
    # easily and quickly interogate the socket to get the source IP address
    # used to connect to this subnet which we can then print out to make for
    # and easy copy/paste in the APIC UI.
    ip = [(s.connect((args.apicip, 80)), s.getsockname()[0], s.close()) for s in [
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
    print "serving at:"
    print "http://" + str(ip) + ":" + str(args.port) + args.location
    print "https://" + str(ip) + ":" + str(args.sslport) + args.location
    print
    try:
        serve_forever([http_server, https_server])
    except KeyboardInterrupt:
        print "Exiting..."


if __name__ == '__main__':
    main()