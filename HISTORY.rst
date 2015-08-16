Release History
---------------

1.1.3 (2015-8-16)
+++++++++++++++++

**Features Added**

- Added a request types filter to allow filtering based on request type, i.e
  POST, GET, undefined, EventChannelMessage, all.  The all option allows all
  request types to be logged and is the default.  Please see the `-ty` and
  `--type` options.
- Slightly revised excludes to allow any exclude based on class name or rn when
  initialized programtically.
- Added aaaLogout, HDfabricOverallHealth5min-0, and all to the excludes as
  options from the CLI.
- Bump version to 1.1.3.

**Bug Fixes**

- handle excludes for registered functions, previously classes that inherited
  SimpleAciUiLogServer or SimpleLogDispatcher had to handle this themselves.

1.1.2 (??)
++++++++++

**Features Added**

- ??

**Bug Fixes**

- ??

1.1.1 (2014-11-24) - date does not seem right... 
++++++++++++++++++++++++++++++++++++++++++++++++

**Features Added**

- Threading support added via the ThreadingSimpleAciUiLogServer class, this
  prevents one request that is being processed from blocking another request
  from being processed.
- Support for HTTPS sessions (#6)
- The standalone script starts both a http and https server and allows
  connections to be established on each independently
- More robust logging by using logging from the standard library
- Pretty printing payload and response elements
- **Experimental** Stripping of the imdata field - may be removed in the future
- Added the following options to the standalone script: --exclude (-e),
  --sslport (-s), --cert (-c), --delete-imdata (-d), --nice-output (-n)
- Release history (this file)
- Total count of objects added to the logging output
- Added responses for GET requests from the servers that indicate the server
  is working

**Bug Fixes**

- Reformatted the logging to be consistent

1.0.1 (2014-11-24)
++++++++++++++++++

**First Release**

Features:

- Handles the following log messages types from the APIC Remote Logging feature:
  GET, POST, Event Channel Message, undefined
- HTTP session support
- Subclassing of SimpleAciUiLogServer class allows for interesting applications
  to be built
- Callbacks can be registered to handle the different supported methods
- Standalone scripts are installed that allow for a default log server to be
  used easily using one of these: acilogserv, SimpleAciUiLogServer.py,
  SimpleAciUiLogServer
- The standalone script supports the --apicip (-a), –port (-p), --location (-l),
  --logrequests (-r) options.