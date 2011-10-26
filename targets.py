#!/usr/bin/env python
import unittest
import sys
import os

class TARGET:
    def __init__(self, **kwargs):
        self._content = dict()
        map(lambda param: self.set(param, kwargs[param]), kwargs)

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
        return "%s=%s" %(self._category, self._content)

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


class TargetTest(unittest.TestCase):
    def test_abstract_init(self):
        t = TARGET_IP(ip="127.0.0.1")
        self.assertTrue("ip" in t._params)


if __name__ == '__main__':
    if os.environ.has_key("TEST"):
        unittest.main()
