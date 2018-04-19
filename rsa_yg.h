
#ifndef _RSA_YG_H_
#define _RSA_YG_H_



int generate_key(int nbits, char *n, char *e, char *d);
int encrypt(const char * plain_text, const int p_len, 
        const char * key_n, const char *key_e, char *cipher);
int decrypt(const char * cipher_text, const int c_len, 
        const char * key_n, const char * key_d, char *plain);


#endif
