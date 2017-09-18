all: suncrypt sundec

suncrypt : 
	gcc -o suncrypt suncrypt.c `libgcrypt-config --cflags --libs` -lm
sundec : 
	gcc -o sundec sundec.c `libgcrypt-config --cflags --libs` -lm
clean:
	rm  suncrypt sundec
