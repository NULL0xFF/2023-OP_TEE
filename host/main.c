/* 2023-01 System and Network Security

   Chungnam National University Sys&NetSec Term Project
   OP-TEE File Encryption Host Application

   Created-By: Ji Myoung Ha <noplayer40600@gmail.com>
   Student-ID: 201802162 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>
#include <TEEencrypt_ta.h>

#define PLAIN_TEXT_FILE "plaintext.txt"
#define CIPHER_TEXT_FILE "ciphertext.txt"
#define ENCRYPTED_KEY_FILE "encryptedkey.txt"
#define RSA_TEXT_FILE "rsa_output.txt"

#define RSA_KEY_SIZE 2048
#define RSA_MAX_PLAIN_LEN_2048 214 // (2048 / 8) - 42(padding)
#define RSA_CIPHER_LEN_2048 (RSA_KEY_SIZE / 8)

char *read_data(char *fileName)
{
    FILE *filePointer = NULL;
    size_t fileSize;
    char *fileData = NULL;

    filePointer = fopen(fileName, "r");
    if (filePointer == NULL)
    {
        fprintf(stderr, "Error: Unable to open file %s\n", fileName);
        exit(EXIT_FAILURE);
    }

    fseek(filePointer, 0, SEEK_END);
    fileSize = ftell(filePointer);
    rewind(filePointer);

    fileData = (char *)malloc(fileSize);
    if (fileData == NULL)
    {
        fprintf(stderr, "Error: Unable to allocate memory for %zu bytes\n", fileSize + 1);
        fclose(filePointer);
        exit(EXIT_FAILURE);
    }

    if (fread(fileData, sizeof(char), fileSize, filePointer) != fileSize)
    {
        fprintf(stderr, "Error: Unable to read file data\n");
        fclose(filePointer);
        free(fileData);
        exit(EXIT_FAILURE);
    }

    fclose(filePointer);
    return fileData;
}

uint32_t read_value(char *fileName)
{
    FILE *filePointer = NULL;
    uint32_t value = 0;

    filePointer = fopen(fileName, "r");
    if (filePointer == NULL)
    {
        fprintf(stderr, "Error: Unable to open file %s\n", fileName);
        exit(EXIT_FAILURE);
    }

    fscanf(filePointer, "%u", &value);

    fclose(filePointer);
    return value;
}

void write_data(char *fileName, char *string)
{
    FILE *filePointer = NULL;

    filePointer = fopen(fileName, "w");
    if (filePointer == NULL)
    {
        fprintf(stderr, "Error: Unable to write file %s\n", fileName);
        exit(EXIT_FAILURE);
    }

    fprintf(filePointer, "%s", string);
    fclose(filePointer);
}

void write_value(char *fileName, uint32_t value)
{
    FILE *filePointer = NULL;

    filePointer = fopen(fileName, "w");
    if (filePointer == NULL)
    {
        fprintf(stderr, "Error: Unable to write file %s\n", fileName);
        exit(EXIT_FAILURE);
    }

    fprintf(filePointer, "%u\n", value);
    fclose(filePointer);
}

void encrypt(char *fileName)
{
    TEEC_Result result;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation;
    TEEC_SharedMemory sharedMemory;
    TEEC_UUID uuid = TA_TEEencrypt_UUID;
    uint32_t error_origin;

    char *inputString;
    size_t inputLength;

    /* Read file */
    inputString = read_data(fileName);
    inputLength = strlen(inputString);

    /* Initialize TA */
    result = TEEC_InitializeContext(NULL, &context);
    result = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &error_origin);

    /* Allocate shared memory */
    sharedMemory.size = inputLength;
    sharedMemory.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    result = TEEC_AllocateSharedMemory(&context, &sharedMemory);

    /* Copy data into shared memory */
    memcpy(sharedMemory.buffer, inputString, inputLength);
    free(inputString);

    /* Generate a random key inside TA */
    result = TEEC_InvokeCommand(&session, TA_TEEencrypt_CMD_CAESAR_GEN_KEY, NULL, &error_origin);

    /* Encrypt the value */
    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].memref.parent = &sharedMemory;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = inputLength;

    result = TEEC_InvokeCommand(&session, TA_TEEencrypt_CMD_CAESAR_ENC_VALUE, &operation, &error_origin);

    write_data(CIPHER_TEXT_FILE, sharedMemory.buffer);

    /* Encrypt the random key */
    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);

    result = TEEC_InvokeCommand(&session, TA_TEEencrypt_CMD_CAESAR_ENC_KEY, &operation, &error_origin);

    write_value(ENCRYPTED_KEY_FILE, operation.params[0].value.a);

    /* Close TA */
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
}

/* from rsa_encrypt of optee_rsa_example */
void encrypt_rsa(char *fileName)
{
    TEEC_Result result;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation;
    TEEC_UUID uuid = TA_TEEencrypt_UUID;
    uint32_t error_origin;

    char plain[RSA_MAX_PLAIN_LEN_2048];
    char cipher[RSA_CIPHER_LEN_2048];
    char *inputString;
    size_t inputLength;

    /* Read file */
    inputString = read_data(fileName);
    inputLength = strlen(inputString);

    /* Initialize TA */
    result = TEEC_InitializeContext(NULL, &context);
    result = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &error_origin);

    /* Copy only RSA_MAX_PLAIN_LEN_2048 bytes of data into char array */
    memcpy(plain, inputString, RSA_MAX_PLAIN_LEN_2048 - 1);
    plain[RSA_MAX_PLAIN_LEN_2048 - 1] = '\0';

    free(inputString);

    /* Generate a rsa key inside TA */
    result = TEEC_InvokeCommand(&session, TA_TEEencrypt_CMD_RSA_GEN_KEY, NULL, &error_origin);

    /* Encrypt the value */
    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_MEMREF_TEMP_OUTPUT,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].tmpref.buffer = plain;
    operation.params[0].tmpref.size = RSA_MAX_PLAIN_LEN_2048;
    operation.params[1].tmpref.buffer = cipher;
    operation.params[1].tmpref.size = RSA_CIPHER_LEN_2048;

    result = TEEC_InvokeCommand(&session, TA_TEEencrypt_CMD_RSA_ENC_VALUE, &operation, &error_origin);

    write_data(RSA_TEXT_FILE, operation.params[1].tmpref.buffer);

    /* Close TA */
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
}

void decrypt(char *cipherFileName, char *keyFileName)
{
    TEEC_Result result;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation;
    TEEC_SharedMemory sharedMemory;
    TEEC_UUID uuid = TA_TEEencrypt_UUID;
    uint32_t error_origin;

    char *cipherString;
    size_t cipherLength;
    uint32_t key;

    /* Read files */
    cipherString = read_data(cipherFileName);
    cipherLength = strlen(cipherString);
    key = read_value(keyFileName);

    /* Initialize TA */
    result = TEEC_InitializeContext(NULL, &context);
    result = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &error_origin);

    /* Allocate shared memory */
    sharedMemory.size = cipherLength;
    sharedMemory.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    result = TEEC_AllocateSharedMemory(&context, &sharedMemory);

    /* Copy data into shared memory */
    memcpy(sharedMemory.buffer, cipherString, cipherLength);
    free(cipherString);

    /* Decryte the value */
    memset(&operation, 0, sizeof(operation));

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
                                            TEEC_VALUE_INPUT,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].memref.parent = &sharedMemory;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = cipherLength;
    operation.params[1].value.a = key;

    result = TEEC_InvokeCommand(&session, TA_TEEencrypt_CMD_CAESAR_DEC_VALUE, &operation, &error_origin);

    write_data(PLAIN_TEXT_FILE, sharedMemory.buffer);

    /* Close TA */
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
}

void print_options(char *programName)
{
    printf("Usage: %s [-e [FILE] [ALGORITHM] | -d [FILE] [FILE]]\n", programName);
    printf("Encrypt or decrypt given file in TEE(Trusted Execution Environment)\n\n");
    printf("Options:\n");
    printf("\t-e\tencrypt the input file using give algorithm\n\t\tcaesar\n\t\trsa (214 bytes))\n");
    printf("\t-d\tdecrypt the input file\n\t\t(only caesar)\n");
}

int main(int argc, char *argv[])
{
    if (argc == 2 && strcmp(argv[1], "-h") == 0)
    {
        print_options(argv[0]);
    }
    else if (argc == 4 && strcmp(argv[1], "-e") == 0 && strcmp(argv[3], "caesar") == 0)
    {
        encrypt(argv[2]);
    }
    else if (argc == 4 && strcmp(argv[1], "-e") == 0 && strcmp(argv[3], "rsa") == 0)
    {
        encrypt_rsa(argv[2]);
    }
    else if (argc == 4 && strcmp(argv[1], "-d") == 0)
    {
        decrypt(argv[2], argv[3]);
    }
    else
    {
        print_options(argv[0]);
        return 1;
    }
    return 0;
}