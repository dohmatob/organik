build:
	make -C src/core build
	make -C src/SIPutils build
	make -C src/libnetsnmp build

install:	
	make -C src/core install
	make -C src/SIPutils install
	make -C src/libnetsnmp install

clean:	
	make -C src/core clean
	make -C src/libnetsnmp clean
	make -C src/SIPutils clean