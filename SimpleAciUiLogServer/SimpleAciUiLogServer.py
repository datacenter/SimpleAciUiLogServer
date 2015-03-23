#!/usr/bin/env python

"""A Simple HTTP server that acts as a remote API Inspector for the APIC GUI.

Written by Mike Timm (mtimm@cisco.com)
Based on code written by Fredrik Lundh & Brian Quinlan.
"""

from argparse import ArgumentParser
import BaseHTTPServer
import cgi
import json
import logging
import os
import re
import select
import signal
import SocketServer
import socket
import ssl
from StringIO import StringIO
import sys
import tempfile

try:
    import fcntl
except ImportError:
    fcntl = None

SERVER_CERT = """
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
    """A class to dispatch log messages."""
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

    def __init__(self, allow_none=False, excludes=None):
        """Initialize a SimpleLogDispatcher instance."""
        self.funcs = {}
        self.instance = None
        self.allow_none = allow_none
        if excludes is None:
            self.excludes = []
        else:
            self.excludes = excludes

    def register_instance(self, instance):
        """Register an instance of a class to dispatch to."""
        self.instance = instance

    def register_function(self, function, name=None):
        """Registers a function to respond to Log requests.

        The optional name argument can be used to set a Unicode name
        for the function.
        """
        if name is None:
            name = function.__name__
        self.funcs[name] = function

    def dispatch(self, method, params):
        """Dispatch log messages."""
        method = method.replace(" ", "")
        self._dispatch(method, params)

    def _dispatch(self, method, params):
        """Internal dispatch method."""
        func = None
        try:
            # check to see if a matching function has been registered
            func = self.funcs[method]
        except KeyError:
            if self.instance is not None:
                # check for a _dispatch method
                if hasattr(self.instance, '_dispatch'):
                    return self.instance.dispatch(method, params)
                else:
                    func = method

        if func is not None:
            return func(**params)
        else:
            # Log some default things if no functions are registered.
            # this also handles any excludes passed in to ignore
            # logs that may match a certain parameter.
            datastring = ""
            paramkeys = params.keys()
            if 'data' not in paramkeys:
                level = logging.DEBUG
                datastring = "No data found"
            else:
                level = self._get_loglevel(**params)
                method = self._get_method(**params)
                url = self._get_url(method, **params)
                payload = self._get_payload(method, **params)
                response, response_dict = self._get_response(**params)
                total_count = self._get_total_count(response_dict)
                # return if we should exclude this log message
                if self._excludes(method, url):
                    return ""
                datastring += "    method: {0}\n".format(method)
                datastring += "       url: {0}\n".format(url)
                datastring += "   payload: {0}\n".format(payload)
                datastring += "    # objs: {0}\n".format(total_count)
                datastring += "  response: {0}\n".format(
                    self._strip_imdata(response_dict))
            logging.log(level, datastring)
            return datastring

    def _excludes(self, method, url):
        """Internal method to exclude certain types of log messages."""
        if method != 'GET':
            return False
        for excl in self.excludes:
            if excl == "subscriptionRefresh" or excl == "aaaRefresh":
                if str(excl) + ".json" in url:
                    return True
            elif excl == "topInfo":
                if "info.json" in url:
                    return True
        return False

    @staticmethod
    def _get_total_count(response_dict):
        """Extract object count if any."""
        try:
            return response_dict['total_count']
        except KeyError:  # bug
            return '0'

    @staticmethod
    def _get_response(**params):
        """Extract the respone if any."""
        try:
            response = params['data']['response']
            response_dict = json.loads(response)
        except KeyError:
            response = "None"
            response_dict = {}
        return response, response_dict

    def _get_payload(self, method, **params):
        """Extract the payload if any."""
        try:
            payload = params['data']['payload']
            if self.prettyprint:
                payload = "\n" + json.dumps(json.loads(payload),
                                            indent=self.indent)
        except KeyError:
            payload = "N/A" if method == "Event Channel Message" else "None"
        return payload

    @staticmethod
    def _get_url(method, **params):
        """Extract the URL."""
        try:
            url = params['data']['url']
        except KeyError:
            url = "N/A" if method == "Event Channel Message" else "None"
        return url

    @staticmethod
    def _get_method(**params):
        """Extract the HTTP method (verb)."""
        try:
            return params['data']['method']
        except KeyError:
            return None

    def _get_loglevel(self, **params):
        """Exract the loglevel if any."""
        try:
            preamble = params['data']['preamble']
            return self.loglevel[preamble.split(" ")[1]]
        except KeyError:
            return logging.DEBUG

    def _strip_imdata(self, json_dict):
        """Strip out the imdata."""
        if 'imdata' not in json_dict.keys():
            return "None"
        if self.strip_imdata:
            # Yeah we knowingly return an invalid json string
            return self._pretty_print(json_dict['imdata'])
        else:
            return self._pretty_print(json_dict)

    def _pretty_print(self, json_dict):
        """Pretty print the logging message."""
        if self.prettyprint:
            return "\n" + json.dumps(json_dict, indent=self.indent)
        return json.dumps(json_dict)


class SimpleLogRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """A class to handle log requests."""
    def __init__(self, request, client_address, server,
                 app_name='SimpleAciUiLogServer'):
        """Initialize an instance of this class."""
        # Instantiate the base class
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request,
                                                       client_address, server)
        self.log_paths = None
        self.app_name = app_name

    @property
    def log_paths(self):
        """A property to return log_paths."""
        return self._log_paths

    @log_paths.setter
    def log_paths(self, value):
        """A property to set log_paths."""
        self._log_paths = value

    @property
    def app_name(self):
        """A property to get app_name."""
        return self._app_name

    @app_name.setter
    def app_name(self, value):
        """A property to set app_name."""
        self._app_name = value

    def is_log_path_valid(self):
        """Make sure the log_paths is valid."""
        if self.log_paths:
            return self.path in self.log_paths
        else:
            # If .log_paths is empty, just assume all paths are legal
            return True

    def send_200_resp(self, response, content_type):
        """Send a HTTP 200 (OK) response."""
        self.send_response(200)
        self.send_header("Content-type", content_type)
        if response is not None:
            resplen = str(len(response))
        else:
            resplen = 0
        self.send_header("Content-length", resplen)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        if response is not None:
            self.wfile.write(response)

    def do_GET(self):  # pylint:disable=invalid-name
        """Handle HTTP GET requests.

        Simply returns a small amount of info so you can tell the server is
        functioning.
        """
        if not self.is_log_path_valid():
            self.report_404()
            return
        scheme = "https" if self.server.cert is not None else "http"
        resp = '<html>'
        resp += '<head>\n'
        resp += '  <title>{0}</title>\n'.format(self.app_name)
        resp += '</head>\n'
        resp += '<body>\n'
        resp += '  <center>\n'
        resp += '    <h2>{0} is working via {1}</h2>\n'.format(self.app_name,
                                                               scheme.upper())
        resp += '  </center>\n'
        resp += '  <p>Please point your APIC at:<br /><br />'
        ip_add = [(s.connect((self.client_address[0], 80)), s.getsockname()[0],
                  s.close()) for s in [socket.socket(socket.AF_INET,
                                                     socket.SOCK_DGRAM)]][0][1]
        resp += '      {0}://{1}:{2}{3}</p>'.format(scheme, ip_add,
                                                    self.server.server_address[
                                                        1],
                                                    self.path)
        resp += '</body>\n'
        resp += '</html>'
        self.send_200_resp(resp, "text/html")

    def do_POST(self):  # pylint:disable=invalid-name
        """Handle HTTP/S POST requests.

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
            chunk_list = []
            while size_remaining:
                chunk_size = min(size_remaining, max_chunk_size)
                chunk = self.rfile.read(chunk_size)
                if not chunk:
                    break
                chunk_list.append(chunk)
                size_remaining -= len(chunk_list[-1])
            data = ''.join(chunk_list)

            data = self.decode_request_content(StringIO(data))
            if data is None:
                return  # response has been sent

            if 'data' in data.keys() and 'method' in data['data'].keys():
                response = self.server.dispatch(data['data']['method'], data)
            else:
                response = None

        except Exception:  # This should only happen if the module is buggy
            # internal error, report as HTTP server error
            self.send_response(500)
            raise
        else:
            # got a valid LOG response
            self.send_200_resp(response, "text/plain")

    @staticmethod
    def extract_form_fields(item):
        """Extract form fields from a POST."""
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
        """Decode the request content based on content-type."""
        content_type = self.headers.get("Content-Type", "notype").lower()
        if 'application/x-www-form-urlencoded' in content_type:
            # The data is provided in a urlencoded format.  Unencode it into
            # cgi FieldStorage/MiniFieldStorage objects in a form container
            form = cgi.FieldStorage(
                fp=datafile,
                headers=self.headers,
                environ=dict(REQUEST_METHOD='POST',
                             CONTENT_TYPE=self.headers['Content-Type'])
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
        """Report a HTTP 404 error."""
        self.send_response(404)
        response = 'No such page'
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_request(self, code='-', size='-'):
        """Selectively log an accepted request."""
        if self.server.log_requests:
            BaseHTTPServer.BaseHTTPRequestHandler.log_request(self, code, size)


class SimpleAciUiLogServer(SocketServer.TCPServer,
                           SimpleLogDispatcher):
    """A simple server to handle ACI UI logging."""
    allow_reuse_address = True
    _send_traceback_header = False

    def __init__(self, addr, cert=None,
                 request_handler=SimpleLogRequestHandler,
                 log_requests=False, allow_none=False, bind_and_activate=True,
                 location=None, excludes=None, app_name='SimpleAciUiLogServer'):
        """Initialize an instance of this class."""
        self.log_requests = log_requests
        self._cert = cert
        self.daemon = True
        if excludes is None:
            excludes = []

        if location is not None:
            if not location.startswith("/"):
                location = "/" + str(location)
            request_handler.log_paths = [location]

        request_handler.app_name = app_name

        SimpleLogDispatcher.__init__(self, allow_none=allow_none,
                                     excludes=excludes)
        SocketServer.TCPServer.__init__(self, addr, request_handler,
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
        """The name of the file containing the server certificate for https."""
        return self._cert

    @cert.setter
    def cert(self, value):
        """Set the name of the file with the server certificate for https."""
        self._cert = value


# Simple dispatch methods.  You can register these and override the default
# behavior of just printing the data out.
# def undefined(**params):
# logging.debug("Got an undefined, params: {0}".format(params))
#
#
# def GET(**params):
#    #pass #- this would ignore all get's
#    logging.debug("Got a GET, params: {0}".format(params))
#
#
# def POST(**params):
#    logging.debug("Got a POST, params: {0}".format(params))
#
#
# def HEAD(**params):
#    logging.debug("Got a HEAD, params: {0}".format(params))
#
#
# def DELETE(**params):
#    logging.debug("Got a DELETE, params: {0}".format(params))
#
#
# def EventChannelMessage(**params):
#    logging.debug("Got an Event Channel Message, params: {0}".format(params))


# use a threaded server so multiple connections can send data simultaneously
class ThreadingSimpleAciUiLogServer(SocketServer.ThreadingMixIn,
                                    SimpleAciUiLogServer):
    """Threading SimpleAciUiLogServer.

    So that concurrent connections do not block.
    """
    pass


# purposely not part of ThreadingSimpleAciUiLogServer
def serve_forever(servers, poll_interval=0.5):
    """Handle n number of threading servers.

    For non-threading servers simply use the native server_forever function.
    """
    while True:
        ready, wait, excep = select.select(servers, [], [], poll_interval)
        for server in servers:
            if server in ready:
                server.handle_request()


def main():
    """The main function for when this is run as a standalone script."""

    # This is used to store the certificate filename
    cert = ""

    # Setup a signal handler to catch control-c and clean up the cert temp file
    # No way to catch sigkill so try not to do that.
    # noinspection PyUnusedLocal
    def sigint_handler(sig, frame):
        """Handle interrupt signals."""
        if not args.cert:
            try:
                os.unlink(cert)
            except OSError:
                pass
        print "Exiting..."
        sys.exit(0)

    parser = ArgumentParser('Remote APIC API Inspector and GUI Log Server')

    parser.add_argument('-a', '--apicip', required=False, default='8.8.8.8',
                        help='If you have a multihomed system, where the ' +
                             'apic is on a private network, the server will ' +
                             'print the ip address your local system has a ' +
                             'route to 8.8.8.8.  If you want the server to ' +
                             'print a more accurate ip address for the ' +
                             'server you can tell it the apicip address.')

    parser.add_argument('-c', '--cert', type=str, required=False,
                        help='The server certificate file for ssl ' +
                             'connections, default="server.pem"')

    parser.add_argument('-d', '--delete_imdata', action='store_true',
                        default=False, required=False,
                        help='Strip the imdata from the response and payload')

    parser.add_argument('-e', '--exclude', action='append', nargs='*',
                        default=[], choices=['subscriptionRefresh',
                                             'aaaRefresh',
                                             'topInfo'],
                        help='Exclude certain types of common noise queries.')

    parser.add_argument('-i', '--indent', type=int, default=2, required=False,
                        help='The number of spaces to indent when pretty ' +
                             'printing')

    parser.add_argument('-l', '--location', default='/apiinspector',
                        required=False,
                        help='Location that transaction logs are being ' +
                             'sent to, default=/apiinspector')

    parser.add_argument('-n', '--nice-output', action='store_true',
                        default=False, required=False,
                        help='Pretty print the response and payload')

    parser.add_argument('-p', '--port', type=int, required=False, default=8987,
                        help='Local port to listen on, default=8987')

    parser.add_argument('-s', '--sslport', type=int, required=False,
                        default=8443,
                        help='Local port to listen on for ssl connections, ' +
                             'default=8443')

    parser.add_argument('-r', '--requests-log', action='store_true',
                        default=False, required=False,
                        help='Log server requests and response codes to ' +
                             'standard error')

    parser.add_argument('-t', '--title', default='SimpleAciUiLogServer',
                        required=False,
                        help='Change the name shown for this application ' +
                             'when accessed with a GET request')

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s - \n%(message)s')
    if args.exclude:
        # Flatten the list
        args.exclude = [val for sublist in args.exclude for val in sublist]

    if not args.location.startswith("/"):
        args.location = "/" + str(args.location)

    ThreadingSimpleAciUiLogServer.prettyprint = args.nice_output
    ThreadingSimpleAciUiLogServer.indent = args.indent
    ThreadingSimpleAciUiLogServer.strip_imdata = args.delete_imdata

    # Instantiate a http server
    http_server = ThreadingSimpleAciUiLogServer(("", args.port),
                                                log_requests=args.requests_log,
                                                location=args.location,
                                                excludes=args.exclude,
                                                app_name=args.title)

    if not args.cert:
        # Workaround ssl wrap socket not taking a file like object
        cert_file = tempfile.NamedTemporaryFile(delete=False)
        cert_file.write(SERVER_CERT)
        cert_file.close()
        cert = cert_file.name
        print("\n+++WARNING+++ Using an embedded self-signed certificate for " +
              "HTTPS, this is not secure.\n")
    else:
        cert = args.cert

    # Instantiate a https server as well
    https_server = ThreadingSimpleAciUiLogServer(("", args.sslport),
                                                 cert=cert,
                                                 location=args.location,
                                                 log_requests=args.requests_log,
                                                 excludes=args.exclude,
                                                 app_name=args.title)

    signal.signal(signal.SIGINT, sigint_handler)  # Or whatever signal

    # Example of registering a function for a specific method.  The funciton
    # needs to exist of course.  Note:  undefined seems to be the same as a
    # GET but the logging facility on the APIC seems to get in a state where
    # instead of setting the method properly it sets it to undefined.
    # These registered functions could then be used to take specific actions or
    # be silent for specific methods.
    # http_server.register_function(GET)
    # http_server.register_function(POST)
    # http_server.register_function(HEAD)
    # http_server.register_function(DELETE)
    # http_server.register_function(undefined)
    # http_server.register_function(EventChannelMessage)

    # This simply sets up a socket for UDP which has a small trick to it.
    # It won't send any packets out that socket, but this will allow us to
    # easily and quickly interogate the socket to get the source IP address
    # used to connect to this subnet which we can then print out to make for
    # and easy copy/paste in the APIC UI.
    ip_add = [(s.connect((args.apicip, 80)), s.getsockname()[0], s.close()) for
              s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]

    print("Servers are running and reachable via:\n")
    print("http://" + str(ip_add) + ":" + str(args.port) + args.location)
    print("https://" + str(ip_add) + ":" + str(args.sslport) + args.location + "\n")
    print("Make sure your APIC(s) are configured to send log messages: " +
          "welcome username -> Start Remote Logging")
    print("Note: If you connect to your APIC via HTTPS, configure the " +
          "remote logging to use the https server.")
    serve_forever([http_server, https_server])


if __name__ == '__main__':
    main()
