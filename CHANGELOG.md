# 0.3.1

* Fix panics on select_all

* Use rustls for platforms that ring works on

# 0.3.0

* Support DNS over TLS

* Support dispatching rules

* Default ports can now be ignored in the DNS address

* Move explanations of configurations to the comments of a config template.

**Config file of version 0.2.\* is not supported.** 

# 0.2.3

* Returns SERVFAIL when no response is available.

* Reset TCP connection when timeout occurs.

# 0.2.2

* Reset TCP connection immediately if an error occurs.

# 0.2.1

* Fix panics when no result is available.

* Change the timeout to 5 seconds.

# 0.2.0

* Use config file instead of command line arguments.

* Support TCP upstream servers.

* Support any number of upstream servers.

* Support customizing rules.

# 0.1.0

* Query the local DNS server and foreign DNS server at the same time.

* Choose the appropriate response according to *chnroutes*.
