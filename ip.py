import IPy

class IpIterator(IPy.IP):
  def __init__(self, data, **kwargs):
      IPy.IP.__init__(self, data, **kwargs)
      self._position = 0
      self._n = self.__len__()
  
  def next(self):
      if self._position == self._n:
          raise StopIteration
      current = self[self._position]
      self._position += 1
      return current.strNormal()
      
if __name__ == "__main__":
    ipiter = IpIterator("192.168.46.0/24")
    while True:
      print ipiter.next()