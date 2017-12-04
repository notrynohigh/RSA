/******************************************************************************
 * File: RSA_Ecrypt.c
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
/** Include ------------------------------------------------------------------*/
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "RSA_Encrypt.h"

/** static variable ---------------------------------------------------------*/
static RSA_PrivateKey_t gRSA_PrivateKey = {0 , 0};
static RSA_PublicKey_t  gRSA_PublicKey = {0, 0};

/** static functions --------------------------------------------------------*/
static RSA_ErrorCode_t RSA_CheckPrime(RSA_U32 n)
{
	RSA_U32 i = 0;
	if(n < 1)
	{
		return -1;
	}
	for(i = 2;i < n;i++)
	{
		if((n % i) == 0)
		{
			return RSA_ERROR;
		}
	}
	return RSA_SUCCESS;
}


RSA_ErrorCode_t RSA_CreateKey(RSA_U32 prime_1, RSA_U32 prime_2, RSA_U32 e)
{
	RSA_U32 euler_n;
	RSA_U32 prime_number_d, multiply_n;
	RSA_U32 i = 0;
	
	if(RSA_SUCCESS != RSA_CheckPrime(prime_1) || RSA_SUCCESS != RSA_CheckPrime(prime_2))
	{
		RSA_DEBUG("number invalid...\n\r");
		return RSA_ERROR;
	}
	multiply_n = prime_1 * prime_2;
	euler_n = (prime_1 - 1) * (prime_2 - 1);
	if(e < 1 || e > euler_n)
	{
		RSA_DEBUG("e param error;must between 1 and %d\n\r", euler_n);
		return RSA_ERROR;
	}
	
	for(i = 0;i < euler_n;i++)
	{
		if((i * e - 1) % euler_n == 0)
		{
			break;
		}
	}
	if(i >= euler_n)
	{
		return RSA_ERROR;
	}
	prime_number_d = i;
	RSA_DEBUG("RSA_PublicKey: %d, %d\n\r",multiply_n, e);
	RSA_DEBUG("RSA_PrivateKey: %d, %d\n\r",multiply_n, prime_number_d);	
	return RSA_SUCCESS;
}


RSA_ErrorCode_t RSA_ConfigPublicKey(RSA_U32 n, RSA_U32 e)
{
	gRSA_PublicKey.n = n;
	gRSA_PublicKey.e = e;
	RSA_DEBUG("RSA_PublicKey:%d, %d\n\r", gRSA_PublicKey.n, gRSA_PublicKey.e);
	return RSA_SUCCESS;
}

RSA_ErrorCode_t RSA_ConfigPrivateKey(RSA_U32 n, RSA_U32 d)
{
	gRSA_PrivateKey.d = d;
	gRSA_PrivateKey.n = n;
	RSA_DEBUG("gRSA_PrivateKey:%d, %d\n\r", gRSA_PrivateKey.n, gRSA_PrivateKey.d);
	return RSA_SUCCESS;
}

RSA_U32 RSA_Encrypt(RSA_U8 *text , RSA_U8 *result, RSA_U32 len)
{
	RSA_U32 i = 0, j = 0, c = 0, tmp_c = 0;
	if(result == RSA_NULL)
	{
		RSA_DEBUG("result invalid !\n\r");
		return 0;
	}
	if(gRSA_PublicKey.e == 0 || gRSA_PublicKey.n == 0)
	{
		RSA_DEBUG("please config public key !\n\r");
		return 0;
	}
	
	for(i = 0;i < len;i++)
	{
		tmp_c = text[i];
		c = text[i];
		for(j = 1; j < gRSA_PublicKey.e; j++)
		{
			tmp_c = (tmp_c * c) % gRSA_PublicKey.n;
		}
		((RSA_U32 *)result)[i] = tmp_c;
	}
	return (i * sizeof(RSA_U32));
}

RSA_U32 RSA_Decrypt(RSA_U8 *text, RSA_U8 *result, RSA_U32 len)
{
	RSA_U32 i = 0, j = 0;
	RSA_U64 c = 0, tmp_c = 0;
	if(result == RSA_NULL)
	{
		RSA_DEBUG("buff invalid !\n\r");
		return 0;
	}
	if(gRSA_PrivateKey.d == 0 || gRSA_PrivateKey.n == 0)
	{
		RSA_DEBUG("please config private key !\n\r");
		return 0;
	}
	for(i = 0;i < (len / sizeof(int));i++)
	{
		tmp_c = ((RSA_U32 *)text)[i];
		c = ((RSA_U32 *)text)[i];
		for(j = 1; j < gRSA_PrivateKey.d; j++)
		{
			tmp_c = (tmp_c * c) % gRSA_PrivateKey.n;
		}
		result[i] = (RSA_U8)(tmp_c & 0xff);
	}
	return i;
}



