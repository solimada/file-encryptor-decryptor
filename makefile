all: cleancrypt cleandec suncrypt sundec

cleancrypt:
	rm -f suncrypt

cleandec:
	rm -f sundec

suncrypt:
	gcc suncrypt.c -lstdc++ -lgcrypt -o suncrypt

sundec:
	gcc sundec.c -lstdc++ -lgcrypt -o sundec
