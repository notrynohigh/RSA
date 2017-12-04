/******************************************************************************
 * File: RSA_Ecrypt.h
 * Author: Bean 
 * Email: notrynohigh@outlook.com
 * Every one can use this file free !
 ******************************************************************************
 *create public key and private key :
 *1. select two prime - prime_1 and  prime_2
 *2. multiply: prime_1 * prime_2 = n 
 *3. calculate euler(φ(n)) : euler = (prime_1 - 1) * (prime_2 - 1)
 *4. select a prime between 1 and euler : e
 *5. find out d : ed - 1 = kφ(n)
 *6. public key : (n, e) ; private key: (n, d) ;
 ******************************************************************************
 *encrypt:
 *1.m[e] ≡ c (mod n)
 *decrypt:
 *2.c[d] ≡ m (mod n)
 ******************************************************************************/


#ifndef __RSA_ENCRYPT__
#define __RSA_ENCRYPT__

/******************************************************************************
 *  basic data type
 ******************************************************************************/
typedef unsigned char  RSA_U8;
typedef signed char    RSA_S8;
typedef unsigned short RSA_U16;
typedef signed short   RSA_S16;
typedef unsigned int   RSA_U32;
typedef signed int     RSA_S32;

typedef unsigned long long int   RSA_U64;
typedef signed long long int     RSA_S64;

#define RSA_NULL    ((void *)0)
/******************************************************************************
 *  define
 ******************************************************************************/
#define RSA_DEBUG_ENABLE      1

#if RSA_DEBUG_ENABLE
#define RSA_DEBUG(...)    printf(__VA_ARGS__)
#else
#define RSA_DEBUG(...) 
#endif

/******************************************************************************
 *  typedef enum
 ******************************************************************************/
typedef enum
{
	RSA_ERROR,
	RSA_SUCCESS,
	RSA_MEMORY_ERROR,
	RSA_OTHERS
}RSA_ErrorCode_t;

/******************************************************************************
 *  typedef struct
 ******************************************************************************/
typedef struct
{
	RSA_U32 n;
	RSA_U32 e;
}RSA_PublicKey_t;

typedef struct
{
	RSA_U32 n;
	RSA_U32 d;
}RSA_PrivateKey_t;


/******************************************************************************
 * public functions
 ******************************************************************************/

RSA_ErrorCode_t RSA_CreateKey(RSA_U32 prime_1, RSA_U32 prime_2, RSA_U32 e);

RSA_ErrorCode_t RSA_ConfigPublicKey(RSA_U32 n, RSA_U32 e);
RSA_ErrorCode_t RSA_ConfigPrivateKey(RSA_U32 n, RSA_U32 d);

/**
 * RSA encrypt
 * text: the data which you want to encrypt.
 * result: the result of this function 
 * Len: the length of text .
 * return : the length of result . 
 *        0 : error 
 */
RSA_U32 RSA_Encrypt(RSA_U8 *text , RSA_U8 *result, RSA_U32 len);

/**
 * RSA decrypt
 * text: the data which you want to decrypt.
 * result: the result of this function 
 * Len: the length of text .
 * return : the length of result . 
 *        0 : error 
 */
RSA_U32 RSA_Decrypt(RSA_U8 *text, RSA_U8 *result, RSA_U32 len);



#endif
/******************************************************************************
 *  Reserved !
 ******************************************************************************/






























