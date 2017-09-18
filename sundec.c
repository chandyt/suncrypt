#include<stdio.h>
#include<gcrypt.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	//read the argumets
	char strPassword[50];	
	char *inputFileName;
	char *outputFileName ;

	if(argc <3){
		printf("Invalid number of arguments: sundec <filename>  [-d < port >][-l] \n");
		exit(0);
	}
	int isSocket=0;
	inputFileName = argv[1];

	if(strcmp(argv[2], "-l")==0){
		int newFileNameLength = strlen(inputFileName)-3;
		outputFileName=malloc(sizeof(char) *  newFileNameLength+1);
		strncpy(outputFileName, inputFileName, newFileNameLength);
		outputFileName[newFileNameLength]='\0';
	}else if(strcmp(argv[2], "-d")==0){
		isSocket=1;
		int newFileNameLength = strlen(inputFileName);
		outputFileName=malloc(sizeof(char) *  newFileNameLength+1);
		outputFileName=inputFileName;
		outputFileName[newFileNameLength]='\0';
	}
	
	FILE * isFileExist;
	isFileExist = fopen(outputFileName, "r");
	if (isFileExist){
		printf("ERROR in Creating Output file: %s exists \n", outputFileName);
		fclose(isFileExist);
		return 33;
	}
	
	if(isSocket == 1){

		if(argc <4){
			printf("Invalid number of arguments: sundec <filename>  -d < port > >\n");
			exit(0);
		}
		// Read from Port
		printf("\nWaiting for connections. \n");  
		char socketRecvBuffer[256];

		unsigned int destPORT=atoi(argv[3]);
		struct sockaddr_in server, client;

		int socketID = socket(AF_INET, SOCK_STREAM, 0);
 		bzero((char *) &server, sizeof(server));
		
		server.sin_family= AF_INET;
		server.sin_port= htons(destPORT);
		server.sin_addr.s_addr= INADDR_ANY;
		
		int bindStatus = bind(socketID, (struct sockaddr *)&server, sizeof(server));
		int listenStatus = listen(socketID, 5);

		socklen_t clientLength=sizeof(client);
		int connectStatus = accept(socketID, (struct sockaddr *)  &client, &clientLength);
		
		char *recvTempFile="socketRecv.txt"; 
		FILE *tempSocketFile = fopen(recvTempFile,"w");
		int receivedSize=0;
		
		while(1){
			// Write received data to File
			bzero(socketRecvBuffer, 256);
			receivedSize = read(connectStatus, socketRecvBuffer, 256);
			if(receivedSize == 0){
				fclose(tempSocketFile);
				break;
			}
			fwrite(socketRecvBuffer, sizeof(char), receivedSize, tempSocketFile);
		}
		close(socketID);
		printf("\nInbound file.\n");
		inputFileName=recvTempFile;
	}

	//check password'	
	printf("Enter Password: ");
	scanf("%s", strPassword);

	char *strSalt = "NaCl";
	char *strKey= (char *) malloc(32);
	int errHandler= gcry_kdf_derive(strPassword, strlen(strPassword), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, strSalt, strlen(strSalt), 4096,32, strKey);

	printf("\nKey: ");
	for(int i=0; i<32; i++){
		printf("%02X " ,strKey[i]);
	}


	//read file from disk
	FILE *inputFile = fopen(inputFileName, "r");
	char *inputBuffer = NULL;
	char *receivedHMAC = NULL;
	int fileSize = 0;

	int digestLength = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
	if(inputFile){
		fseek(inputFile, 0L, SEEK_END);
		fileSize = ftell(inputFile);
		rewind(inputFile);
		inputBuffer= (char *) malloc(sizeof(char) *  (fileSize-digestLength));
		fread(inputBuffer, sizeof(char), fileSize-digestLength,inputFile);
		receivedHMAC= (char *) malloc(sizeof(char) *  digestLength);
		fread(receivedHMAC, sizeof(char), digestLength,inputFile);
		fclose(inputFile);
	
	}
	//generate hash

	gcry_md_hd_t hmacHandler;
	errHandler=gcry_md_open(&hmacHandler, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);

	errHandler=gcry_md_setkey(hmacHandler,strKey, 32);

        gcry_md_write(hmacHandler, inputBuffer, fileSize-digestLength);

	digestLength = gcry_md_get_algo_dlen(gcry_md_get_algo(hmacHandler)); 
	char *calcHMAC = gcry_md_read(hmacHandler, GCRY_MD_SHA512);
	
	if(strcmp(receivedHMAC, calcHMAC) !=0){
		printf("\nHMAC is corrupted\n");
		exit(62);
	}

	//decrypt
	gcry_cipher_hd_t cipherHandler;
	errHandler = gcry_cipher_open(&cipherHandler, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
	errHandler = gcry_cipher_setkey(cipherHandler, strKey, 32);
	int initVector[4] = {5,8,4,4};
	errHandler = gcry_cipher_setiv(cipherHandler, initVector, sizeof(initVector));
	errHandler = gcry_cipher_decrypt(cipherHandler, inputBuffer, fileSize-digestLength, NULL,0);
	
	FILE *outputFile = fopen(outputFileName,"wx");
	fwrite(inputBuffer, sizeof(char), fileSize-digestLength, outputFile);
	fclose(outputFile);
	printf("\nSuccessfully received and decrypted %s (%d bytes written).\n", outputFileName, fileSize-digestLength);	
	
}



