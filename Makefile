build:
	make -C src/coreutils build
	make -C src/SIPutils build
	make -C src/libnetsnmp build

install:	
	make -C src/coreutils install
	make -C src/SIPutils install
	make -C src/libnetsnmp install

clean:	
	make -C src/coreutils clean
	make -C src/libnetsnmp clean
	make -C src/SIPutils clean