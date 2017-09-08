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

	//generate Key

	int errHandler= gcry_kdf_derive(strPassword, strlen(strPassword), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, strSalt, strlen(strSalt), 4096,32, strKey);


	int i=0;
	for(i=0; i<32; i++){
		printf("%02X " ,strKey[i]);
	}

	//read file contents

	FILE *inputFile = fopen(fileName, "r");
	char *inputBuffer = NULL;
	int fileSize = 0;
	if(inputFile){
		fseek(inputFile, 0, SEEK_END);
		fileSize = ftell(inputFile);
		rewind(inputFile);
		inputBuffer= (char *) malloc(sizeof(char) *  (fileSize+1));
		fread(inputBuffer, sizeof(char), fileSize,inputFile);
		printf("%s", inputBuffer);	//TODO:Remove me	
		fclose(inputFile);
		
	}

	//Do the Encryption
	// TODO:handle the error handler
	gcry_cipher_hd_t cipherHandler;
	errHandler = gcry_cipher_open(&cipherHandler, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);

	errHandler = gcry_cipher_setkey(cipherHandler, strKey, 32);
	int initVector[4] = {5,8,4,4};
	errHandler = gcry_cipher_setiv(cipherHandler, initVector, sizeof(initVector));
	
	errHandler = gcry_cipher_encrypt(cipherHandler, inputBuffer, fileSize, NULL,0);	

	//do the hash function
	
	//Check the flags for file destination

	// Write to File
	strcat(fileName, ".uf");
	FILE *outputFile = fopen(fileName,"w");// TODO: may be change to wx to fail on file exists

	//TODO: handle file exists
	fwrite(inputBuffer, sizeof(char), fileSize, outputFile);
	fclose(outputFile);	
	
	

	// Write to Port
}


