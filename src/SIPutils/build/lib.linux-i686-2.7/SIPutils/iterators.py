def fileLineIterator(fh):
    line = fh.readline().rstrip('\r\n')
    while line:
        yield line
        line = fh.readline().rstrip('\r\n')
    fh.close()

