====================
SimpleAciUiLogServer
====================

A Simple HTTP server that accepts POSTs from the APIC UI as a remote API
Inspector.

The simplest method to use this module is to execute it as a standalone script:

.. code-block:: bash

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

* -a or --apicip: The IP address of an APIC or an IP address on the same subnet
  as the APIC.  This allows the standalone server to be able to print the
  correct IP address when it announces what IP address, port and location
  it is listening on if the server is multi-homed.
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

.. code-block:: python

    >>>
    >>> from SimpleAciUiLogServer.SimpleAciUiLogServer import \
    ... SimpleAciUiLogServer
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

Note that since there were no functions registered for the EventChannelMessage
method, it went the default route which is to print info about the log message.
However, both GET and POST have registered functions and they do different
things than the default dispatch action.

It is also possible to override the \_dispatch method to create your own
dispatch logic, for example rather than dispatch based on method maybe you
would like to dispatch based on subscription id.

Once the server is running, you can start remote logging from the APIC UI by
selecting "Start Remote Logging" from the 'welcome, username' menu in the top
right corner of the APIC UI.

.. image:: https://raw.githubusercontent.com/datacenter/SimpleAciUiLogServer/master/start_remote_logging.png

Then enter the URL the server is listening on:

.. image:: https://raw.githubusercontent.com/datacenter/SimpleAciUiLogServer/master/enter_remote_logging_info.png

If you need to disable the remote logging from the APIC, you can do so from
the same menu and selecting 'Stop Remote Logging.'

.. image:: https://raw.githubusercontent.com/datacenter/SimpleAciUiLogServer/master/stop_remote_logging.png

Limitations: Does not support HTTPS/TLS at this time.

Written by Mike Timm (mtimm@cisco.com)
Based on code written by Fredrik Lundh & Brian Quinlan.
 