#!/usr/bin/env python
import unittest
import sys
import os

class TARGET:
    def __init__(self, **kwargs):
        self._content = dict()
        map(lambda param: self.set(param, kwargs[param]), kwargs) # XXX TODO: should only set params defined in self._params !

    def set(self, param, value):
        """
        Set given parameter to value
        """
        self._content[param] = value
        
    def get(self, param):
        """
        Retrieve paramter vale
        """
        try:
            return self._content[param]
        except KeyError:
            return None

    def __str__(self):
        raw = "%s("%self._category
        for key, item in self._content.iteritems():
            raw += "%s=%s, "%(key,item)
        return raw.rstrip(", ") + ")"

    def getCategory(self):
        return self._category

    def getContent(self):
        return self._content


class TARGET_IP(TARGET):
    """
    Encapsulates a target ip
    """
    _category = "TARGET_IP"
    _params = list(["ip"])


class TARGET_IPRANGE(TARGET):
    """
    Encapsulates a target ip range
    """
    _category = "TARGET_IPRANGE"
    _params = list(["iprange"])


class TARGET_TCP_PORT(TARGET):
    """
    Encapsulates a target tcp port (i.e port + ip)
    """
    _category = "TARGET_TCP_PORT"
    _params = list(["ip", "port"])


class TARGET_TCP_CONNECTION(TARGET):
    """
    Encapsulates a target tcp connection between two peers
    """
    _category = 'TARGET_TCP_CONNECTION'
    _params = ['ipA', 'portA',' ipB', 'portB']


class TARGET_SNMP_SERVICE(TARGET):
    """
    Ecapsulates a target SNMP service
    """
    _category = "TARGET_SNMP_SERVICE"
    _params = list(["ip", "port", "version", "community", "sysdescr", "sysname"])


class TARGET_SIP_SERVICE(TARGET):
    """
    Encapsulates a target SIP service
    """
    _category = "TARGET_SIP_SERVICE"
    _params = list(["ip", "port", "useragent"])


class TARGET_SIP_USER(TARGET):
    """
    Encapsulates a target SIP user
    """
    _category = "TARGET_SIP_USER"
    _params = list(["ip", "port", "useragent", "username", "authentication"])


class TargetTest(unittest.TestCase):
    def test_abstract_init(self):
        t = TARGET_IP(ip="127.0.0.1")
        self.assertTrue("ip" in t._params)


if __name__ == '__main__':
    if os.environ.has_key("TEST"):
        unittest.main()
