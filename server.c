#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<unistd.h> 
#include<pthread.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#define SUCCESS 0
#define FAILURE 1

//#define KEY_LENGTH 256
#define KEY_WORD_LENGTH 32
#define IV_WORD_LENGTH 16

typedef struct ThreadInfo
{
    uint8_t key[KEY_WORD_LENGTH + 1];
    uint8_t iv[IV_WORD_LENGTH + 1];
    int     sock;
} thread_info_t, *thread_info_handler_t;

 
//the thread function
void *connection_handler(void *);


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

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
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
 
int main(int argc , char *argv[])
{
    int socket_desc , client_sock , c;
    struct sockaddr_in server , client;

    init_openssl_lib();
    FILE *fp_key = fopen("symmetric.key", "rw");
    if (!fp_key) printf("file not open\n");
    uint8_t key[KEY_WORD_LENGTH + 1];
    uint8_t iv[IV_WORD_LENGTH + 1];
    read_symmetric_key(fp_key, key, iv);
    key[KEY_WORD_LENGTH] = '\0';
    iv[IV_WORD_LENGTH] = '\0';
    // Save the key and iv to the given file pointer in hex format.
    printf( "key:\n\t");
    for (int i = 0; i < KEY_WORD_LENGTH; ++i)
    {
        printf("%02x", key[i]);
    }
    printf("\niv:\n\t");
    for (int i = 0; i < IV_WORD_LENGTH; ++i)
    {
        printf("%02x", iv[i]);
    }
    printf("\n\n");


     
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("[SOCKET] Could not create socket");
    }
    puts("[SOCKET] Socket created");
     
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 15432 );
     
    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        perror("[SOCKET] bind failed. Error");
        return 1;
    }
    puts("[SOCKET] Bind Done");
     
    //Listen
    listen(socket_desc , 3);
     
    //Accept and incoming connection
    puts("[SOCKET] Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);
    pthread_t thread_id;


    
    while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
    {
        puts("[SOCKET] Connection accepted");
        thread_info_t thread_info;
        thread_info.sock = client_sock;
        memcpy(thread_info.key, key, KEY_WORD_LENGTH);
        memcpy(thread_info.iv, iv, IV_WORD_LENGTH);
         
        if( pthread_create( &thread_id , NULL ,  connection_handler , (void*) &thread_info) < 0)
        {
            perror("[PTHREAD] Could not create thread");
            return 1;
        }
         
        //Now join the thread , so that we dont terminate before the thread
        //pthread_join( thread_id , NULL);
        puts("[PTHREAD] Handler assigned");
    }
     
    if (client_sock < 0)
    {
        perror("[SOCKET] Accept Failed");
        return 1;
    }
    
    close_openssl_lib();
    return 0;
}
 
/*
 * This will handle connection for each client
 * */
void *connection_handler(void *thread_info_handler)
{
    //Get the socket descriptor
    thread_info_t thread_info = *(thread_info_handler_t)thread_info_handler;
    int sock = thread_info.sock;
    thread_info.key[KEY_WORD_LENGTH] = '\0';
    thread_info.iv[IV_WORD_LENGTH] = '\0';
    int read_size;
    char length_arr[4];
    unsigned long length;

    uint8_t hash_value[128];

    puts("=====================================");

    //Receive a message from client
    while( (read_size = recv(sock , length_arr , 4 , 0)) > 0 )
    {
        sscanf(length_arr, "%04lx", &length);
        printf("Plaintext Length: %ld\n", length);
        char *plaintext = (char *)malloc(length + 1);
        read_size = recv(sock , plaintext , length , 0);
        plaintext[length] = '\0';
        printf("Plaintext:\n\t%s\n\n", plaintext);

        read_size = recv(sock , length_arr , 4 , 0);
        sscanf(length_arr, "%04lx", &length);
        char *signature = (char *)malloc(length + 1);
        printf("Signature Length: %ld\n", length);
        read_size = recv(sock , signature , length , 0);
        signature[length] = '\0';
        read_size = recv(sock , length_arr , 4 , 0);
        sscanf(length_arr, "%04lx", &length);
        int signature_len = length;
        printf("Ciphertext Signature:\n\t");
        for (int i = 1; i <= strlen((char *)signature); ++i)
        {
            printf("%02x", (uint8_t)signature[i]);
            if (i % 8 == 0) printf("\n\t");
        }
        printf("\n");

        int len = mydecrypt((uint8_t *)signature, signature_len, thread_info.key, thread_info.iv, hash_value);
        hash_value[len] = '\0';
        printf("Hash Value:\n\t%s\n\n", hash_value);

        uint8_t *hash_value_text = str2md5((uint8_t *)plaintext, strlen((char *)plaintext));
        printf("Hash Value From Plain Text:\n\t%s\n\n", hash_value_text);
        if (strcmp((char *)hash_value, (char *)hash_value_text) == 0)
        {
            puts("Hash Value Match\n");
            write(sock , "True" , strlen("True"));
        }
        else
        {
            puts("Hash Value Do Not Match\n");
            write(sock , "False" , strlen("False"));
        }
    }
     
    if(read_size == 0)
    {
        puts("[SOCKET] Client disconnected");
        fflush(stdout);
    }
    else if(read_size == -1)
    {
        perror("[SOCKET] Recv Failed");
    }

    puts("=====================================");
    return 0;
} 