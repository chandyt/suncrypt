#include<stdio.h>
#include<gcrypt.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h> 
#include <unistd.h>

int main(int argc, char *argv[])
{
	char strPassword[50];	
	char *inputFileName;
	char *outputFileName;
	char *strSalt = "NaCl";
	char *strKey= (char *) malloc(32);
	int isLocal = 0; 

	if(argc <3){
		printf("\nInvalid number of arguments: suncrypt <input file> [-d < IP-addr:port >][-l]\n");
		exit(0);
	}

	inputFileName = argv[1];
	
	if(strcmp(argv[2], "-l")==0){
		isLocal=1;
		int newFileNameLength = strlen(inputFileName)+3;
		outputFileName= malloc(sizeof(char) *  newFileNameLength+1); ;
		strcpy(outputFileName, inputFileName);
		outputFileName[newFileNameLength]='\0';
		strcat(outputFileName, ".uf");
		
		FILE * isFileExist;
		isFileExist = fopen(outputFileName, "r");
		
		if (isFileExist){
			printf("\nERROR in Creating Output file: %s exists \n", outputFileName);
			fclose(isFileExist);
			return 33;
		}
	}


	printf("\nPassword: ");
	scanf("%s", strPassword);
	
	//generate Key
	gcry_kdf_derive(strPassword, strlen(strPassword), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, strSalt, strlen(strSalt), 4096,32, strKey);
	printf("\nKey: ");
	for(int i=0; i<32; i++){
		printf(" %02X " ,(unsigned char) strKey[i]);
	}

	//read file contents
	FILE *inputFile = fopen(inputFileName, "r");
	char *inputBuffer = NULL;
	int fileSize = 0;
	if(inputFile){
		fseek(inputFile, 0, SEEK_END);
		fileSize = ftell(inputFile);
		rewind(inputFile);
		inputBuffer= (char *) malloc(sizeof(char) *  (fileSize));
		fread(inputBuffer, sizeof(char), fileSize,inputFile);
		fclose(inputFile);
	}


/*
	gcry_md_hd_t hmacHandlerTemp;
	errHandler=gcry_md_open(&hmacHandlerTemp, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	errHandler=gcry_md_setkey(hmacHandlerTemp,strKey, 32);
        gcry_md_write(hmacHandlerTemp, inputBuffer, fileSize);
	int digestLengthTemp = gcry_md_get_algo_dlen(gcry_md_get_algo(hmacHandlerTemp)); 
        char *hmacStringTemp = gcry_md_read(hmacHandlerTemp, GCRY_MD_SHA512);
	printf("\nHASH String Before Encryption: %s\n",hmacStringTemp); //for screenshot only
*/
	//Do the Encryption
	gcry_cipher_hd_t cipherHandler;
	gcry_cipher_open(&cipherHandler, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
	gcry_cipher_setkey(cipherHandler, strKey, 32);
	int initVector[4] = {5,8,4,4};
	gcry_cipher_setiv(cipherHandler, initVector, sizeof(initVector));
	gcry_cipher_encrypt(cipherHandler, inputBuffer, fileSize, NULL,0);	

	//do the hash function and add hash to encrypted text
	gcry_md_hd_t hmacHandler;
	gcry_md_open(&hmacHandler, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(hmacHandler,strKey, 32);
        gcry_md_write(hmacHandler, inputBuffer, fileSize);
	int digestLength = gcry_md_get_algo_dlen(gcry_md_get_algo(hmacHandler)); 
        char *hmacString = gcry_md_read(hmacHandler, GCRY_MD_SHA512);
	
	//printf("\nHASH String After Encryption: %s\n",hmacString); //for screenshot only

	if(isLocal == 1){ 
		// Write to File
		FILE *outputFile = fopen(outputFileName,"w");
		fwrite(inputBuffer, sizeof(char), fileSize, outputFile);
		fwrite(hmacString, sizeof(char), digestLength, outputFile);
		fclose(outputFile);
		printf("\nSuccessfully encrypted %s to %s (%d bytes written).\n",  inputFileName, outputFileName, fileSize + digestLength);		
	} else {
		// Write to Port
		if(argc <4){
			printf("\nInvalid number of arguments: suncrypt <input file> -d < IP-addr:port >\n");
			exit(0);
		}
		char * destination = argv[3]; //Stores the destination to a string
		char *destIP=strsep(&destination, ":"); // removes the IP part from the string
		unsigned int destPORT=atoi(strsep(&destination, ":")); // removes the PORT from the string
		struct sockaddr_in remoteSocket;

		int srcSocket = socket(AF_INET, SOCK_STREAM, 0);
		remoteSocket.sin_family= AF_INET;
		remoteSocket.sin_port= htons(destPORT);
		remoteSocket.sin_addr.s_addr= inet_addr(destIP);
		printf("\nTransmitting to %s",argv[3]);

		connect(srcSocket, (struct sockaddr *)  &remoteSocket, sizeof(remoteSocket)); // connect to socket
		write(srcSocket, inputBuffer, fileSize); //write buffer to port
		write(srcSocket, hmacString, digestLength); // write hash to port
		close(srcSocket);
		printf("\nSuccessfully received\n");
	}
}


