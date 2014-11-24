#!/usr/bin/env python
"""
A Simple HTTP server that accepts POSTs from the APIC UI as a remote API
Inspector.

The simplest method to use this module is to execute it as a standalone script:

    $ SimpleAci
    SimpleAciUiLogServer     SimpleAciUiLogServer.py
    $ SimpleAciUiLogServer
    serving at:
    http://10.1.2.11:8987/apiinspector

    08:17:14 DEBUG -
      method: GET
      url: http://10.1.2.1/api/subscriptionRefresh.json?id=72057843163791365
      response: {"imdata":[]}

    08:17:14 DEBUG -
      method: GET
      url: http://10.1.2.1/api/subscriptionRefresh.json?id=72057843163791488
      response: {"imdata":[]}

    08:17:14 DEBUG -
      method: GET
      url: http://10.1.2.1/api/subscriptionRefresh.json?id=72057843163791514
      response: {"imdata":[]}

The standalone script can be invoked using any of these commands:

* SimpleAciUiLogServer
* SimpleAciUiLogServer.py
* acilogserv

The standalone script also allows you to set several options:

* -p or --port: The port the server should listen on.
* -l or --location: The local path that the server should look for, anything
  sent to the server outside of this location will result in the server
  returinging a 404.  The default is /apiinspector
* -r or --logrequests: This will cause the server to log a message about the
  POST request to sys.stderr, the default is False, possible values are True and
  False.

When the module is run as a standalone script it simply prints the log messages
to sys.stdout in a somewhat easy to read format.

You can also import the module and use it as a server as part of another
application.  This provides you with flexibility as it allows you to register
callback functions for each "method" found in the log message.  From this, you
could do things like use the data from the log message for other purposes or
filter out specific logs messages based on the "method."  The methods that the
APIC uses are:

* GET
* POST
* EventChannelMessage
* undefined - NOTE: it seems like this method gets set for unknown reasons.
  I need to investigate it more.

Example:

    >>>
    >>> from SimpleAciUiLogServer.SimpleAciUiLogServer import \
        SimpleAciUiLogServer
    >>> def GET(**kwargs):
    ...     print "Got a GET"
    ...
    >>> def POST(**kwargs):
    ...     print "Kwargs/params: {0}".format(kwargs)
    ...
    >>> server = SimpleAciUiLogServer(("", 8987), location='/acilogs')
    >>> server.register_function(GET)
    >>> server.register_function(POST)
    >>> server.serve_forever()
    Got a GET
    Got a GET
    08:50:52 DEBUG -
      method: Event Channel Message
      response: {"subscriptionId":["72057843163791520","72057843163791488",
      "72057843163791521","72057843163791516"],"imdata":[{"fvTenant":{
      "attributes":{"childAction":"","dn":"uni/tn-mtimm-simple2",
      "modTs":"2014-11-24T12:50:36.706-04:00","rn":"","status":"deleted"}}}]}

    08:50:53 DEBUG -
      method: Event Channel Message
      response: {"subscriptionId":["72057843163791523"],
      "imdata":[{"fvRsTenantMonPol":{"attributes":{"childAction":"",
      "dn":"uni/tn-mtimm-simple2/rsTenantMonPol",
      "modTs":"2014-11-24T12:50:36.706-04:00","rn":"","status":"deleted"}}}]}

    Kwargs/params: {'data': {'url':
    'http://10.1.2.1/api/node/mo/uni.json', 'response': '{"imdata":[]}',
    'preamble': '08:50:53 DEBUG - ', 'method': 'POST', 'payload':
    '{"polUni":{"attributes":{"dn":"uni","status":"modified"},
    "children":[{"fvTenant":{"attributes":{"dn":"uni/tn-mtimm-simple2",
    "status":"deleted"},"children":[]}}]}}'}, 'layout': 'PatternLayout'}
    Got a GET

Note that since we did not register a function for the EventChannelMessage
method, it went the default route which is to print info about the log message.
However, both GET and POST have registered functions and they do different
things than the default dispatch action.

You can also override the _dispatch method to create your own dispatch logic,
for example rather than dispatch based on method maybe you would like to
dispatch based on subscription id.

Once the server is running, you can start remote logging from the APIC UI by
selecting "Start Remote Logging" from the 'welcome, username' menu in the top
left corner of the APIC UI.

Limitations: Does not support HTTPS/TLS at this.

Written by Mike Timm (mtimm@cisco.com)
Based on code written by Fredrik Lundh & Brian Quinlan.
"""

import BaseHTTPServer
from StringIO import StringIO
import SocketServer
import socket
import cgi
import re
from argparse import ArgumentParser

try:
    import fcntl
except ImportError:
    fcntl = None


class SimpleLogDispatcher:
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
            # Print some default things if no functions are registered.
            datastring = ""
            paramkeys = params.keys()
            if 'data' in paramkeys:
                paramkeys2 = params['data'].keys()
                if 'preamble' in paramkeys2:
                    datastring += "{0}\n".format(params['data']['preamble'])
                if 'method' in paramkeys2:
                    datastring += "  method: {0}\n".format(
                        params['data']['method'])
                if 'url' in paramkeys2:
                    datastring += "  url: {0}\n".format(params['data']['url'])
                if 'payload' in paramkeys2:
                    datastring += " payload: {0}\n".format(
                        params['data']['payload'])
                if 'response' in paramkeys2:
                    datastring += "  response: {0}\n".format(
                        params['data']['response'])
            print(datastring)
            return datastring


class SimpleLogRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    log_paths = ['/apiinspector']

    def is_log_path_valid(self):
        if self.log_paths:
            return self.path in self.log_paths
        else:
            # If .log_paths is empty, just assume all paths are legal
            return True

    def do_POST(self):
        """Handles the HTTP POST request.

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
            self.send_response(200)
            self.send_header("Content-type", "text/text")
            if response is not None:
                resplen = str(len(response))
            else:
                resplen = 0
            self.send_header("Content-length", resplen)
            self.end_headers()
            self.wfile.write(response)

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
                    # Not sure what the layout item is for, but append it.
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

    def __init__(self, addr, requestHandler=SimpleLogRequestHandler,
                 logRequests=False, allow_none=False, bind_and_activate=True,
                 location=None):
        self.logRequests = logRequests

        if location is not None:
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


# Simple dispatch methods.  You can register these and override the default
# behavior of just printing the data out.
#def undefined(**params):
#    print "Undefined"
#    #print "Got an undefined, params: {0}".format(params)
#
#def GET(**params):
#    print "GET"
#    #pass
#    #print "Got a GET, params: {0}".format(params)
#
#def POST(**params):
#    #pass
#    print "POST"
#    #print "Got a POST, params: {0}".format(params)
#
#def HEAD(**params):
#    #pass
#    print "HEAD"
#    #print "Got a HEAD, params: {0}".format(params)
#
#def DELETE(**params):
#    #pass
#    print "DELETE"
#    #print "Got a DELETE, params: {0}".format(params)
#
#def EventChannelMessage(**params):
#    #pass
#    print "EventChannelMessage"
#    #print "Got an Event Channel Message, params: {0}".format(params)


def main():
    parser = ArgumentParser('Remote APIC API Inspector and GUI Log Server')
    parser.add_argument('-p', '--port', help='Local port to listen on,' +
                                             ' default=8987', default=8987,
                        type=int,
                        required=False)
    parser.add_argument('-l', '--location', help='Location that transaction ' +
                                                 'logs are being sent to, ' +
                                                 'default=/apiinspector',
                        default="/apiinspector", required=False)
    parser.add_argument('-r', '--logrequests', help='Log server requests and ' +
                                                    'response codes to ' +
                                                    'standard error',
                        action='store_true', default=False, required=False)
    args = parser.parse_args()

    server = SimpleAciUiLogServer(("", args.port),
                                  logRequests=args.logrequests,
                                  location=args.location)
    # Example of registering a function for a specific method.  The funciton
    # needs to exist of course.  Note:  undefined seems to be the same as
    # POST or EventChannelMessage but the logging facility on the APIC seems
    # to get in a state where instead of setting the method properly it sets it
    # to undefined.
    # These registered functions could then be used to take specific actions or
    # be silent for specific methods.
    #server.register_function(GET)
    #server.register_function(POST)
    #server.register_function(HEAD)
    #server.register_function(DELETE)
    #server.register_function(undefined)
    #server.register_function(EventChannelMessage)
    ip = [(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close()) for s in [
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
    print "serving at:"
    print "http://" + str(ip) + ":" + str(args.port) + args.location
    print
    server.serve_forever()


if __name__ == '__main__':
    main()