/*
 * rsa_yg.h
 *
 *  Created on: 2018-4-11
 *      Author: xuyang
 */

#ifndef _RSA_YG_H_
#define _RSA_YG_H_



int generate_key(const int nbits, char *n, int *n_len, char *e, int *e_len, char *d, int *d_len);
int encrypt(const char * plain_text, const int p_len, const char * key_n, const int n_len, const char *key_e, const int e_len, char *cipher, int *c_len);
int decrypt(const char * cipher_text, const int c_len, const char * key_n, const int n_len, const char * key_d, const int d_len, char *plain);


#endif

