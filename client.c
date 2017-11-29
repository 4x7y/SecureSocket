#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#define SUCCESS 0
#define FAILURE 1

#define KEY_LENGTH 256
#define KEY_WORD_LENGTH 32
#define IV_WORD_LENGTH 16

#ifdef __APPLE__
#define RANDOM_FILE "/dev/random"
#else
#define RANDOM_FILE "/dev/urandom"
#endif

uint8_t *str2md5(const uint8_t *str, int length) {
    int n;
    MD5_CTX c;
    uint8_t digest[16];
    char *out = (char*)malloc(33);

    MD5_Init(&c);

    while (length > 0) {
        if (length > 512) {
            MD5_Update(&c, str, 512);
        } else {
            MD5_Update(&c, str, length);
        }
        length -= 512;
        str += 512;
    }

    MD5_Final(digest, &c);

    for (n = 0; n < 16; ++n) {
        snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }

    return (uint8_t *)out;
}

static int sock;
static int socket_connect(char * ip_addr, int port)
{
    struct sockaddr_in server;

    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        perror("[SOCKET] Could not create socket");
        return FAILURE;
    }
    printf("[SOCKET] Socket created\n");

    server.sin_addr.s_addr = inet_addr(ip_addr);
    server.sin_family = AF_INET;
    server.sin_port = htons( port );

    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("[SOCKET] Connect failed. Error");
        return FAILURE;
    }

    printf("[SOCKET] Connected\n");
    return SUCCESS;
}

static int socket_send(char *message, int length)
{
    //Send some data
    if( send(sock , message, length, 0) < 0)
    {
        perror("[SOCKET] Send Failed");
        return FAILURE;
    }

    printf("[SOCKET] Socket Send %d Bytes\n", length);
    return SUCCESS;
}

static int socket_recv(char *reply, int length)
{
    //Receive a reply from the server
    if( recv(sock , reply , length , 0) < 0)
    {
        puts("[SOCKET] Recv Failed");
        return FAILURE;
    }

    return SUCCESS;
}


static int socket_close()
{
    shutdown(sock, 0);
    return SUCCESS;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int myencrypt(uint8_t *plaintext, int plaintext_len, uint8_t *key,
  uint8_t *iv, uint8_t *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialise the encryption operation. IMPORTANT - ensure you use a key
    // and IV size appropriate for your cipher
    // In this example we are using 256 bit AES (i.e. a 256 bit key). The
    // IV size for *most* modes is the same as the block size. For AES this
    // is 128 bits
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

    // Provide the message to be encrypted, and obtain the encrypted output.
    // EVP_EncryptUpdate can be called multiple times if necessary

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
    ciphertext_len = len;

    // Finalise the encryption. Further ciphertext bytes may be written at
    // this stage.

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int mydecrypt(uint8_t *ciphertext, int ciphertext_len, uint8_t *key,
  uint8_t *iv, uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialise the decryption operation. IMPORTANT - ensure you use a key
    // and IV size appropriate for your cipher
    // In this example we are using 256 bit AES (i.e. a 256 bit key). The
    // IV size for *most* modes is the same as the block size. For AES this
    // is 128 bits
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

    // Provide the message to be decrypted, and obtain the plaintext output.
    // EVP_DecryptUpdate can be called multiple times if necessary

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
    plaintext_len = len;

    // Finalise the decryption. Further plaintext bytes may be written at
    // this stage.

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

static void init_openssl_lib()
{
    // Initialise the library
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

static void close_openssl_lib()
{
    // Clean up
    EVP_cleanup();
    ERR_free_strings();
}

static int generate_signature(uint8_t *key, uint8_t *iv, uint8_t *package, uint8_t *signature)
{
    // Generate hash value
    uint8_t *hash_value = str2md5(package, strlen((char *)package));
    printf("Hash Value:\n\t%s\n\n", hash_value);

    // Encrpyt hash value
    init_openssl_lib();
    int len = myencrypt(
        (uint8_t *)hash_value, strlen((char *)hash_value), key, iv, signature);

    printf("Generate Signature:\n\t");
    for (int i = 1; i <= strlen((char *)signature); ++i)
    {
        printf("%02x", signature[i]);
        if (i % 8 == 0) printf("\n\t");
    }
    printf("\n");
    // uint8_t dd[128];
    // len = mydecrypt(signature, len, key, iv, dd);
    // dd[len] = '\0';
    // printf("Decrypt Result:\n\t%s\n\n", dd);

    close_openssl_lib();
    free(hash_value);

    return len;
}

static int build_package(uint8_t *key, uint8_t *iv, char *plaintext, uint8_t *package)
{
    time_t rawtime;
    struct tm * timeinfo;
    uint8_t signature[1024], text[1024];

    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    printf ( "Current local time and date:\n\t%s\n", asctime (timeinfo) );
    sprintf((char *)text, "%s%s", asctime (timeinfo), plaintext);
    printf ("Plain Text:\n\t%s\n\n", plaintext);
    int len = generate_signature(key, iv, text, signature);
    //signature[len] = '\0';
    sprintf((char *)package, "%04lx%s%04lx%s%04x", strlen((char *)text), text, strlen((char *)signature), signature, len);

    return SUCCESS;
}



static int generate_symmetric_key(FILE *fp_key)
{
    // Numbers generated by the rand and random APIs are not 
    // cryptographically secure. In OS X, given the same initial 
    // seed value, both functions reproducibly generate a 
    // consistent sequence of values each time you run them,
    // and neither generates an equally distributed set of 
    // possible values.
    // 
    // In OS X, you can get cryptographically secure pseudorandom
    // numbers by reading bytes from the /dev/random device file.
    // Each byte from this file is a cryptographically random value
    // from 0-255. By concatenating these bytes, you can generate
    // a random number of an arbitrary size.
    FILE *fp = fopen(RANDOM_FILE, "r");

    if (!fp) {
        perror("rand getter");
        return FAILURE;
    }
    
    // An AES-256 symmetic key, which KEY_WORD_LENGTH = (256 << 8)
    uint8_t value[KEY_WORD_LENGTH] = {0};
    uint8_t iv[IV_WORD_LENGTH] = {0};
    for (int i = 0; i < KEY_WORD_LENGTH; ++i)
    {
        value[i] = fgetc(fp);
    }
    for (int i = 0; i < IV_WORD_LENGTH; ++i)
    {
        iv[i] = fgetc(fp);
    }

    // Save the key and iv to the given file pointer in hex format.
    fprintf(fp_key, "key\t");
    for (int i = 0; i < KEY_WORD_LENGTH; ++i)
    {
        fprintf(fp_key, "%02x", value[i]);
    }
    fprintf(fp_key, "\niv\t");
    for (int i = 0; i < IV_WORD_LENGTH; ++i)
    {
        fprintf(fp_key, "%02x", iv[i]);
    }
    fprintf(fp_key, "\n");

    return SUCCESS;
}


static int read_symmetric_key(FILE *fp_key, uint8_t *key, uint8_t *iv)
{
    int32_t tmp;
    fscanf(fp_key, "key:\t");
    for (int i = 0; i < KEY_WORD_LENGTH; ++i)
    {
        fscanf(fp_key, "%02x", &tmp);
        key[i] = (uint8_t)tmp;
    }
    fscanf(fp_key, "\niv:\t");
    for (int i = 0; i < IV_WORD_LENGTH; ++i)
    {
        fscanf(fp_key, "%02x", &tmp);
        iv[i] = (uint8_t)tmp;
    }

    return SUCCESS;
}

void print_package(char *package)
{
    printf("package:\n\t");
    for (int i = 1; i <= strlen(package); ++i)
    {
        printf("%02x", (uint8_t)package[i]);
        if (i % 8 == 0) printf("\n\t");
    }
    printf("\n\n");
}

int main(int argc, char *argv[])
{
    if (argc == 2 && strcmp(argv[1], "-g") == 0)
    {
        FILE *fp_key = fopen("./symmetric.key", "w");
        generate_symmetric_key(fp_key);
        fclose(fp_key);

        printf("AES-256 symmetic key generated\n");

        return SUCCESS;
    }
    else if (argc != 1)
    {
        printf("use \'-g\' to generate symmetic key\n");
        return FAILURE;
    }

    FILE* fp_key = fopen("./symmetric.key", "rw");
    if (fp_key == 0) 
    {
        printf("use \'-g\' to generate symmetic key\n");
        return FAILURE;
    }

    uint8_t key[KEY_WORD_LENGTH + 1];
    uint8_t iv[IV_WORD_LENGTH + 1];
    read_symmetric_key(fp_key, key, iv);
    key[KEY_WORD_LENGTH] = '\0';
    iv[IV_WORD_LENGTH] = '\0';

    char ip_addr[] = "127.0.0.1";
    int  port = 15432;
    socket_connect(ip_addr, port);
    
    uint8_t package[1024];
    uint8_t plaintext[1024];
    build_package(key, iv, ip_addr, package);
    print_package((char *)package);
    socket_send((char *)package, strlen((char *)package));
    socket_recv((char *)plaintext, 1024);
    
    printf("Plain Text Received:\n\t%s\n", (char *)plaintext);    
    socket_close();

    return SUCCESS;
}
