#include<stdio.h>
#include<gcrypt.h>

void main(int argc, char *argv[])
{
	//read the argumets
	char strPassword[50];	// TODO: Change to char *
	char *fileName;
	fileName = argv[1];
	char *outFileName = "myTestFileDec.txt" ; //TODO: Change me
	FILE *outputFile = fopen(outFileName,"w");// TODO: may be change to wx to fail on file exists

	//check password'	

	printf("Enter Password: ");
	scanf("%s", strPassword);

	char *strSalt = "NaCl";
	char *strKey= (char *) malloc(32);
	int errHandler= gcry_kdf_derive(strPassword, strlen(strPassword), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, strSalt, strlen(strSalt), 4096,32, strKey);


	int i=0;
	for(i=0; i<32; i++){
		printf("%02X " ,strKey[i]);
	}


	//read file from disk

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
	//read hash
	//decrupt
	// TODO:handle the error handler
	gcry_cipher_hd_t cipherHandler;
	errHandler = gcry_cipher_open(&cipherHandler, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
	errHandler = gcry_cipher_setkey(cipherHandler, strKey, 32);
	int initVector[4] = {5,8,4,4};
	errHandler = gcry_cipher_setiv(cipherHandler, initVector, sizeof(initVector));
	
	errHandler = gcry_cipher_decrypt(cipherHandler, inputBuffer, fileSize, NULL,0);	

	fwrite(inputBuffer, sizeof(char), fileSize, outputFile);
	fclose(outputFile);
	

}



