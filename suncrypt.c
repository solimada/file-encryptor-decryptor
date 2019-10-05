
// Suncrypt
// gcc suncrypt.c -lstdc++ -lgcrypt -o suncrypt

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

	char ipAddress [17];
	int port;

	char* password;
	password = malloc(10);

	const char* SALT = "NaCl";
	unsigned long iter = 4096;

	const int KEYSIZE = 16;
	char key [KEYSIZE];
	int IV[4] = {5,8,4,4};

	FILE* unencryptedFile;
	FILE* encryptedFile;
	char* fileContents;
	size_t fileSize;

	char* encryptedFileName;
	encryptedFileName = malloc(strlen(argv[1]) + 4);
	strncpy(encryptedFileName, argv[1],strlen(argv[1]));
	encryptedFileName [strlen(argv[1])] = '.';
	encryptedFileName [strlen(argv[1]) + 1] = 'u';
	encryptedFileName [strlen(argv[1]) + 2] = 'f';
	encryptedFileName [strlen(argv[1]) + 3] = '\0';





	if (argc < 3){
		exit(0);
	}

	flag = argv[2][1]; //-l or -d

	if (flag == 'd'){
		for (index = 0; index < strlen(argv[3]); ++index) {
			if (argv[3][index] == ':'){
				break;
			}
		}
		port = atoi(&argv[3][index+1]);
		strncpy(ipAddress, argv[3], index);
		ipAddress[index] = '\0';

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
	printf("\n\n");



	//open file
 	unencryptedFile = fopen(argv[1],"r");
	if (unencryptedFile == NULL){
		printf("File does not exist\n");
		exit(1);
	}
	fseek(unencryptedFile, 0, SEEK_END);
	fileSize = ftell(unencryptedFile);
	if(fileSize > 16){
		fileSize += (fileSize % 16); //add padding to match key length
	} else {
		fileSize += 16 - fileSize;
	}
	fileContents = (char *) calloc(fileSize, 1); //allocate space for file contents
	fseek(unencryptedFile, 0, SEEK_SET); //reset file position to beginning
	fread(fileContents,sizeof(char),fileSize,unencryptedFile);
	fclose(unencryptedFile);

	//print testfile hash
	gcry_md_hd_t testfilehash;
	if(gcry_md_open(&testfilehash, GCRY_MD_SHA512, 0)){
		printf("Failed to open HMAC handle\n");
		exit(1);
	}
	gcry_md_write(testfilehash, fileContents, fileSize);
	char* sha512;
	sha512 = gcry_md_read(testfilehash, GCRY_MD_SHA512);
	printf("testfile SHA512 hash:");
	for (index=0; index<64;++index){
			printf("%02x", (unsigned char)sha512[index]);
	}
	printf("\n\n");



	//encrypt with AES128
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

	//in-place encryption
	int error;
	if(error = gcry_cipher_encrypt(hd, fileContents, fileSize, NULL, 0)){
		printf("Failed to encrypt:%s\n",gcry_strerror(error));
		exit(1);
	}



	gcry_md_write(testfilehash, fileContents, fileSize);
	char* encsha512;
	encsha512 = gcry_md_read(testfilehash, GCRY_MD_SHA512);
	printf("Encrypted testfile SHA512 hash:");
	for (index=0; index<64;++index){
			printf("%02x", (unsigned char)encsha512[index]);
	}
	printf("\n\n");




	//HMAC
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

	gcry_md_write(mhd, fileContents, fileSize);
	gcry_md_final(mhd); //NOTE:might not be needed
	char* hmac;
	hmac = gcry_md_read(mhd, GCRY_MD_SHA512);

//FILE* temp;
//temp = fopen("hmac","wb");

	//write ouput to file
	if(fopen(encryptedFileName,"r") != NULL){ //check if output file already exists
		printf("Error: outfile already exists\n");
		return 33;
	}
	encryptedFile = fopen(encryptedFileName,"wb"); //open in binary mode cuz encrypted
	fwrite(fileContents,sizeof(char),fileSize,encryptedFile); //write encrypted contents
//	fseek(encryptedFile,0,SEEK_END);
	fwrite(hmac,sizeof(char),64,encryptedFile); //write hmac
	//fwrite(hmac,sizeof(char),64,temp); //write hmac
	fclose(encryptedFile);

	//gcry_md_reset(mhd);
	gcry_cipher_close(hd);


	return 0;
}
