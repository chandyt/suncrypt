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
		//printf("%02X " ,strKey[i]);
	}


	//do the hash function and get hash data



	//read file from disk

	FILE *inputFile = fopen(fileName, "r");
	char *inputBuffer = NULL;
	char *receivedHash = NULL;
	int fileSize = 0;


	int digestLength = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
	//printf("%d", digestLength); //TODO:Remove me
    	//digestLength =0 ;
	if(inputFile){
		fseek(inputFile, 0L, SEEK_END);
		fileSize = ftell(inputFile);
		//rewind(inputFile);
		fseek(inputFile, 0, SEEK_SET);
		printf("File Size : %d\n", fileSize-digestLength);
		inputBuffer= (char *) malloc(sizeof(char) *  (fileSize-digestLength));
		fread(inputBuffer, sizeof(char), fileSize-digestLength,inputFile);
		printf("\nBuffer %s\n", inputBuffer);	//TODO:Remove me

		//receivedHash= (char *) malloc(sizeof(char) *  digestLength);
		//fread(receivedHash, sizeof(char), digestLength,inputFile);
		//printf("Hash %s\n", receivedHash);	//TODO:Remove me
	
		fclose(inputFile);
		
	}
	//read hash

	gcry_md_hd_t hmacHandler;
	

	errHandler=gcry_md_open(&hmacHandler, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);

	errHandler=gcry_md_setkey(hmacHandler,strKey, 32);

        gcry_md_write(hmacHandler, inputBuffer, fileSize-digestLength);

	digestLength = gcry_md_get_algo_dlen(gcry_md_get_algo(hmacHandler)); 
	//digestLength=0;
	//printf("%d", digestLength); //TODO:Remove me
    
        char *calchmacString = gcry_md_read(hmacHandler, GCRY_MD_SHA512);


	//decrupt
	// TODO:handle the error handler



	gcry_cipher_hd_t cipherHandler;
	errHandler = gcry_cipher_open(&cipherHandler, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
	errHandler = gcry_cipher_setkey(cipherHandler, strKey, 32);
	int initVector[4] = {5,8,4,4};
	errHandler = gcry_cipher_setiv(cipherHandler, initVector, sizeof(initVector));
	
	errHandler = gcry_cipher_decrypt(cipherHandler, inputBuffer, fileSize-digestLength, NULL,0);	
	printf("Dec Text: %s\n", inputBuffer);	//TODO:Remove me
	fwrite(inputBuffer, sizeof(char), fileSize-digestLength, outputFile);
	fclose(outputFile);
	

}



