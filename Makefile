install:	
	make -C src/coreutils install
	make -C src/SIPutils install
	make -C src/packets install
	# make -C src/SNMPutils install

clean:	
	make -C src/coreutils clean
	make -C src/SIPutils clean
	make -C src/packets clean
	# make -C src/SNMPutils clean