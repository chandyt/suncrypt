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

	if(strcmp(argv[2], "-l")==0){ //Replace .uf from extension
		int newFileNameLength = strlen(inputFileName)-3;
		outputFileName=malloc(sizeof(char) *  newFileNameLength+1);
		strncpy(outputFileName, inputFileName, newFileNameLength);
		outputFileName[newFileNameLength]='\0';
	}else if(strcmp(argv[2], "-d")==0){ // keep the outputfilename= inputfilename
		isSocket=1; // enabling socket connection
		int newFileNameLength = strlen(inputFileName);
		outputFileName=malloc(sizeof(char) *  newFileNameLength+1);
		outputFileName=inputFileName;
		outputFileName[newFileNameLength]='\0';
	}
	
	//chekc if outputfile exists
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
		
		bind(socketID, (struct sockaddr *)&server, sizeof(server));
		listen(socketID, 5);

		socklen_t clientLength=sizeof(client);
		int connectionID = accept(socketID, (struct sockaddr *)  &client, &clientLength);
		
		char *recvTempFile="socketRecv.txt"; //temp file to store the incoming buffer
		FILE *tempSocketFile = fopen(recvTempFile,"w");
		int receivedSize=0;
		
		while(1){
			// Write received data to File
			bzero(socketRecvBuffer, 256);
			receivedSize = read(connectionID, socketRecvBuffer, 256);
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

	//get password'	
	printf("Enter Password: ");
	scanf("%s", strPassword);

	char *strSalt = "NaCl";
	char *strKey= (char *) malloc(32);
	gcry_kdf_derive(strPassword, strlen(strPassword), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, strSalt, strlen(strSalt), 4096,32, strKey);

	printf("\nKey: ");
	for(int i=0; i<32; i++){
		printf(" %02X " ,(unsigned char)strKey[i]);
	}


	//read file from disk
	FILE *inputFile = fopen(inputFileName, "r");
	char *inputBuffer = NULL;
	char *receivedHMAC = NULL;
	int fileSize = 0;

	int digestLength = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
	if(inputFile){
		fseek(inputFile, 0, SEEK_END);
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
	gcry_md_open(&hmacHandler, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(hmacHandler,strKey, 32);
        gcry_md_write(hmacHandler, inputBuffer, fileSize-digestLength);
	char *calcHMAC = gcry_md_read(hmacHandler, GCRY_MD_SHA512);

	//printf("\nReceived HASH String: %s\n",receivedHMAC); //for screenshots
	//printf("\nCalculated HASH String: %s\n",calcHMAC); //for screenshots

	if(memcmp(receivedHMAC, calcHMAC, digestLength) !=0){
		printf("\nHMAC is corrupted\n");
		exit(62);
	}

	//decrypt
	gcry_cipher_hd_t cipherHandler;
	gcry_cipher_open(&cipherHandler, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
	gcry_cipher_setkey(cipherHandler, strKey, 32);
	int initVector[4] = {5,8,4,4};
	gcry_cipher_setiv(cipherHandler, initVector, sizeof(initVector));
	gcry_cipher_decrypt(cipherHandler, inputBuffer, fileSize-digestLength, NULL,0);
	
	FILE *outputFile = fopen(outputFileName,"wx");
	fwrite(inputBuffer, sizeof(char), fileSize-digestLength, outputFile);
	fclose(outputFile);
	printf("\nSuccessfully received and decrypted %s (%d bytes written).\n", outputFileName, fileSize-digestLength);
	//printf("\nReceived Data: %s\n",inputBuffer); //for screenshots	
	
}



