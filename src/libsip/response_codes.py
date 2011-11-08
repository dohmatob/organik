"""
Here be grouped most important SIP response codes
"""
PROXYAUTHREQ = 407 
AUTHREQ = 401
OKAY = 200
NOTFOUND = 404
INVALIDPASS = 403
TRYING = 100
RINGING = 180
NOTALLOWED = 405 # method not allowed
UNAVAILABLE = 480
INEXISTENTTRANSACTION = 481
BUSYHERE = 486 # Twinkle/1.4.2 is observed to reply as such (should we DoS it ?)
TEMPORARILYUNAVAILABLE = 480 
NOTIMPLEMENTED = 501 #

# Mapped to ISDN Q.931 codes - 88 (Incompatible destination), 95 (Invalid message), 111 (Protocol error)
# If we get something like this, then most probably the remote device SIP stack has troubles with
# understanding / parsing our messages (a.k.a. interopability problems).
BADREQUEST = 400

# Mapped to ISDN Q.931 codes - 34 (No circuit available), 38 (Network out of order), 41 (Temporary failure),
# 42 (Switching equipment congestion), 47 (Resource unavailable)
# Should be handled in the very same way as SIP response code 404 - the prefix is not correct and we should
# try with the next one.
SERVICEUNAVAILABLE = 503
