#include<stdio.h>
#include<gcrypt.h>

void main(int argc, char *argv[])
{
	char strPassword[50];	// TODO: Change to char *
	char *fileName;
	char *strSalt = "NaCl";
	char *strKey= (char *) malloc(32);
	printf("Enter Password: ");
	scanf("%s", strPassword);

	fileName = argv[1];
	printf(fileName); //TODO: Remove me

	int errHandler= gcry_kdf_derive(strPassword, strlen(strPassword), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, strSalt, strlen(strSalt), 4096,32, strKey);


	int i=0;
	for(i=0; i<32; i++){
		printf("%02X " ,strKey[i]);
	}

	
}


