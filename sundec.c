
// Sundec
// gcc sundec.c -lstdc++ -lgcrypt -o sundec

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <gcrypt.h>

//TODO:might need to use secure memory
void initializeGCRYPT(){
	if (!gcry_check_version(GCRYPT_VERSION)){
		printf("failed to initialize library\n");
		exit(1);
	}
	gcry_control(GCRYCTL_DISABLE_SECMEM,0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED,0);
}

int main(int argc, char *argv[]) {

	initializeGCRYPT();

	char flag;
	int index; //index for for loops

	int port;

	char* password;

	const char* SALT = "NaCl";
	unsigned long iter = 4096;

	const int KEYSIZE = 16;
	char key [KEYSIZE];
	int IV[4] = {5,8,4,4};

	char* receivedHmac;
	receivedHmac = (char*)calloc(64,1);

	FILE* decryptedFile;
	FILE* encryptedFile;
	char* fileContents;
	size_t fileSize;

	char decryptedFileName [strlen(argv[1])];
	for (index=0; index<strlen(argv[1]);++index){
		decryptedFileName[index] = '\0';
	}
	strncpy(decryptedFileName, argv[1],strlen(argv[1])-3);
//char* decryptedFileName = "testfiledec";
//printf("%s\n",decryptedFileName );
//return 1;

	if (argc < 3){
		exit(0);
	}

	flag = argv[2][1]; //-l or -d

	if (flag == 'd'){
		port = atoi(argv[3]);
	}
	else if (flag == 'l'){
		printf("local mode!\n");
	}
	else {
		printf("Invalid argument %c\n",flag);
		exit(0);
	}

	printf("Password: ");
	fscanf(stdin,"%ms",&password);

	//generate key
	if(gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, SALT, strlen(SALT), iter, KEYSIZE, key)){
		printf("key derivation function broke\n");
		exit(1);
	}
	printf("Key: "); //print key bytes
	for (index = 0; index < KEYSIZE; ++index){
		printf("%02x ", (unsigned char)key[index]);
	}
	printf("\n");



	encryptedFile = fopen(argv[1],"rb"); //open encrypted file
	if(encryptedFile == NULL){
		printf("Failed to open file\n");
		exit(1);
	}


	//copy contents to buffer
	fseek(encryptedFile, 0, SEEK_END);
	fileSize = ftell(encryptedFile);
	fileContents = (char *) calloc(fileSize-64, 1); //allocate space for file contents
	fseek(encryptedFile, 0, SEEK_SET); //reset file position to beginning
	fread(fileContents,sizeof(char),fileSize-64,encryptedFile);
	fread(receivedHmac,sizeof(char),64,encryptedFile);


	gcry_md_hd_t testfilehash;
	char* cipherAndHMAC;
	cipherAndHMAC = (char *) calloc(fileSize, 1);
	fseek(encryptedFile, 0, SEEK_SET);
	fread(cipherAndHMAC,sizeof(char),fileSize,encryptedFile);
	if(gcry_md_open(&testfilehash, GCRY_MD_SHA512, 0)){
		printf("Failed to open HMAC handle\n");
		exit(1);
	}
	gcry_md_write(testfilehash, cipherAndHMAC, fileSize);
	char* encHMACsha512;
	encHMACsha512 = gcry_md_read(testfilehash, GCRY_MD_SHA512);
	printf("\n\nEncrypted testfile and HMAC SHA512 hash:");
	for (index=0; index<64;++index){
			printf("%02x", (unsigned char)encHMACsha512[index]);
	}
	printf("\n\n");





	//Calc HMAC
	gcry_md_hd_t mhd;
	if(gcry_md_open(&mhd, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC)){
		printf("Failed to open HMAC handle\n");
		exit(1);
	}

//TODO: find out if this is needed
	if(gcry_md_enable(mhd,GCRY_MD_SHA512)){
		printf("Failed to enable HMAC \n");
		exit(1);
	}

	if(gcry_md_setkey(mhd, key, KEYSIZE)){
		printf("Failed to set HMAC key\n");
		exit(1);
	}

	gcry_md_write(mhd, fileContents, fileSize-64);
	gcry_md_final(mhd); //NOTE:might not be needed
	char* hmac;
	hmac = gcry_md_read(mhd, GCRY_MD_SHA512);

	for (index=0;index<64;++index){
		if(hmac[index] != receivedHmac[index]){
			printf("ERROR: HMAC do not match\n");
			printf("%02x ** %02x\n", (unsigned char)hmac[index],(unsigned char)receivedHmac[index]);
			return 62;
		}
	}

	//print HMACS
	printf("received HMAC:");
	for(index=0;index<64;++index){
		printf("%02x ", (unsigned char)receivedHmac[index]);
	}
	printf("\n");
	printf("\ncalculated HMAC:");
	for(index=0;index<64;++index){
		printf("%02x ", (unsigned char)hmac[index]);
	}
	printf("\n\n\n");

//debugging stuff
//FILE* temp1, *temp2, *temp3;
//temp1 = fopen("hmaccalc","wb");
//temp2 = fopen("hmacreceived","wb");
//temp3 = fopen("cihertext","wb");
//fwrite(hmac,sizeof(char),64,temp1);
//fwrite(receivedHmac,sizeof(char),64,temp2);
//fwrite(fileContents,sizeof(char),fileSize-64,temp3);




	//AES128
	gcry_cipher_hd_t hd;
	if(gcry_cipher_open(&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS)){
		printf("Failed to open cipher handle\n");
		exit(1);
	}

	if (gcry_cipher_setkey(hd, key, KEYSIZE)){
		printf("Failed to set key\n");
		exit(1);
	}
//TODO: IV might need to be a buffer?
	if (gcry_cipher_setiv(hd, IV, KEYSIZE)){
		printf("Failed to set IV\n");
		exit(1);
	}
	//in-place decryption
	int error;
	if(error = gcry_cipher_decrypt(hd, fileContents, fileSize-64, NULL, 0)){
		printf("Failed to decrypt:%s\n",gcry_strerror(error));
		exit(1);
	}



	//write output to file
	if(fopen(decryptedFileName,"r") != NULL){ //check if output file already exists
		printf("Error: outfile already exists\n");
		return 33;
	}
	decryptedFile = fopen(decryptedFileName,"w"); //open in binary mode cuz encrypted
	fwrite(fileContents,sizeof(char),fileSize-65,decryptedFile); //write encrypted contents
	fclose(decryptedFile);

	printf("\n\nDecrypted text: \n%s\n\n", fileContents);


	return 0;
}
