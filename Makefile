build:
	make -C src/core build
	make -C src/libsip build
	make -C src/libnetsnmp build

install:	
	make -C src/core install
	make -C src/libsip install
	make -C src/libnetsnmp install

clean:	
	make -C src/core clean
	make -C src/libsip clean
	make -C src/libnetsnmp clean