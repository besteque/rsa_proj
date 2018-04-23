/*
 * rsa_yg.c
 *
 *  Created on: 2018-4-11
 *      Author: xuyang
 */

/********************************************************************
 * <performance announcement>
 *
 * generate_key speed:109.375000 ms
 * encrypt speed:3.515625 ms
 * decrypt speed:3.593750 ms
 * Experimental data from x86_64 GNU/Linux4.4.0-43, i5-6200U 4CPUs @ 2.30GHz
********************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <gmp.h>

#include "rsa_yg.h"
  

//#define BASE 62    //输入输出的数字进制,62=sum(0-9,A-Z,a-z)，但未包含符号
#define BASE 256


/*  
    note:apt-get install libgmp-dev (直接安装，或参照如下源码编译)
    compile: gcc -g -O2 -o demo rsa_test.c -lgmp
        curl https://gmplib.org/download/gmp/gmp-6.1.2.tar.lz -o gmp-6.1.2.tar.lz
        apt install lzip
        lzip -d gmp-6.1.2.tar.lz 
        tar -xvf gmp-6.1.2.tar 
                depend:apt-get install build-essential m4
                ./configure --help
                ./configure [--prefix=/usr --enable-cxx]
                make
                make check 
                make install 生成静态库和动态库到.libs和usr/local/lib
*/


// mpz_getlimbn
int str_to_mpz(const char *text, const int len, mpz_t mp_data)
{
    mp_size_t mp_len;
    int pkg_size = (len+sizeof(mp_limb_t)-1)/sizeof(mp_limb_t);
    mp_limb_t *limb = calloc(pkg_size, sizeof(mp_limb_t));

    mp_len = mpn_set_str(limb, (unsigned char*)text, len, BASE);

    mp_data->_mp_alloc = pkg_size;
    mp_data->_mp_size = mp_len; //mpn_sizeinbase(limb, mp_len, BASE);
    mp_data->_mp_d = limb;
    
    //printf("test _mp_alloc:%d\n" , pkg_size);
    //printf("test _mp_size:%zd\n" , mp_len);

    return 0;
}

int mpz_to_str(const mpz_t mp_data, unsigned char *text, int *len)
{
     //printf("mp_data->_mp_alloc:%d\n" , mp_data->_mp_alloc); // applied
     //printf("mp_data->_mp_size:%d\n" , mp_data->_mp_size);  // used
    *len = mpn_get_str((unsigned char*)text, BASE, mp_data->_mp_d, mp_data->_mp_size);
     //printf("*len:%d\n" , *len);  // used

    return 0;
}


  
// generate two big primes
mpz_t * gen_primes(int nbits, mpz_t p, mpz_t q)  
{    
    mpz_t key_p, key_q;
    gmp_randstate_t grt;
    
    gmp_randinit_default(grt);
    gmp_randseed_ui(grt, time(NULL));
      
    mpz_init(key_p);  
    mpz_init(key_q);  
  
    mpz_urandomb(key_p, grt, nbits / 2);         
    mpz_urandomb(key_q, grt, nbits / 2);
  
    mpz_init(p);
    mpz_init(q);
  
    mpz_nextprime(p, key_p);
    mpz_nextprime(q, key_q);  
  
    mpz_clear(key_p);  
    mpz_clear(key_q);  
  
    return 0;    
}  


/**
 * nbits means prime bit len
 * base64 will make char visible
 * CAUTION:length of n/e/d may be not corresponding, but not larger than nbits/8. 
 *              Laziness comes at a price.
*/
int generate_key(const int nbits, char *n, int *n_len, char *e, int *e_len, char *d, int *d_len)
{
    int ret;
    gmp_randstate_t grt;
    mpz_t p, q, key_n, key_e, key_d, key_fn, gcd; 
    
    gmp_randinit_default(grt);    
    gmp_randseed_ui(grt, time(NULL)); 
    
    gen_primes(nbits, p, q);  
  
    mpz_init(key_n);  
    mpz_init(key_e);
    mpz_init(key_d);
    mpz_init(key_fn);
    mpz_init(gcd);
  
    mpz_mul(key_n, p, q);           //n=p*q  
    mpz_sub_ui(p, p, 1);           //p=p-1  
    mpz_sub_ui(q, q, 1);           //q=q-1  
    mpz_mul(key_fn, p, q);          //φ(n)=(p-1)*(q-1)
    
    do
    {  
        mpz_urandomm(key_e, grt, key_fn);
        mpz_gcd(gcd,key_e,key_fn);   //set e
    }while(mpz_get_ui(gcd)!=1);
    

    // mpz_invert(rop, op1, op2)  ，op1*rop ≡ 1 (mod op2) implies (op1*rop - 1) mod op2 = 0
    ret = mpz_invert(key_d, key_e, key_fn);
    if (ret != 1)
    {
        printf("mpz_invert ret:%d, expect 1\n", ret);
        return -1;
    }        
    
    mpz_to_str(key_n, n, n_len);
    mpz_to_str(key_d, d, d_len); 
    mpz_to_str(key_e, e, e_len);
    
    //free data
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(key_n);
    mpz_clear(key_d);
    mpz_clear(key_e);
    mpz_clear(key_fn);
  
    return 0;  
}



//加密函数
// case nbits=1024 then cihper length=128bytes
// case nbits=2048 then cihper length=256bytes
// CAUTION:p_len must less than key len, other wise, need divide into multi-pkg
int encrypt(const char * plain_text, const int p_len, const char * key_n, const int n_len, const char *key_e, const int e_len, char *cipher, int *c_len)
{
    mpz_t M, C, n, e;

    str_to_mpz(plain_text, p_len, M);
    str_to_mpz(key_n, n_len, n);
    str_to_mpz(key_e, e_len, e);
    
    mpz_init_set_ui(C, 0);  
  
    mpz_powm(C, M, e, n);    

    mpz_to_str(C, cipher, c_len);

    mpz_clear(M);
    mpz_clear(C);
    mpz_clear(n);
    mpz_clear(e);
  
    return 0;  
}  
  

int decrypt(const char * cipher_text, const int c_len, const char * key_n, const int n_len, const char * key_d, const int d_len, char *plain)
{
    int m_len;
    mpz_t M, C, n, d; 
    
    str_to_mpz(cipher_text, c_len, C);
    str_to_mpz(key_n, n_len, n);
    str_to_mpz(key_d, d_len, d);
    
    mpz_init(M);  
  
    mpz_powm(M, C, d, n);

    mpz_to_str(M, plain, &m_len);
    
    mpz_clear(M);
    mpz_clear(C);
    mpz_clear(n);
    mpz_clear(d);
    
    return 0;  
}  
 

#if DEBUG
// gcc -g -O2 -o demo rsa_test.c rsa_yg.c -lgmp
//or
//gcc -c rsa_yg.c -o rsa_yg.o;cp libgmp.a librsa.a;gcc -g -O2 -o demo rsa_test.c -L. -lrsa 
int test_rsa(void)  
{
    double          tt;
    int             loop = 200;
    clock_t         start, end;

    int i,j = 0, len, n_len, d_len, e_len;
    char key_n[KEY_LENGTH + 10] = {0};
    char key_e[KEY_LENGTH + 10] = {0};
    char key_d[KEY_LENGTH + 10] = {0};
    char buf[KEY_LENGTH + 10] = {0};
    char cipher[KEY_LENGTH + 10] = {0};
    char plain[KEY_LENGTH + 10] = {0};

    start   = clock();
    generate_key(KEY_LENGTH, key_n, &n_len, key_e, &e_len, key_d, &d_len);
    end = clock();
    tt = (double) (end - start) / CLOCKS_PER_SEC;
    printf("generate_key speed:%lf ms\n", tt*1000);
    
    //printf("n = %s\n", key_n); 
    //printf("e = %s\n", key_e);
    //printf("d = %s\n", key_d);
  
    printf("pls input data, length must less than:%d\n",KEY_LENGTH/8); 
    //scanf("%s", buf);
    //strcpy(buf, "0\\0./lk0cU-9C083GBFJB/KN V 8989WOH2KLN2W   P ");
    strcpy(buf, "0\\0./lk0cU-9C083GFJB/KN V 8989Wd2fOH2KLN2W   P 0\\0./lN V 8989WOH2KLNN V 8989WOH2KLNN V 8989WOH2KLNk0cU-9C083GBFJB/KN V 8989WOH2");

    len = strlen(buf);


    if (len >= KEY_LENGTH/8)
    {
        printf("len:%d too long,must less than KEY_LENGTH/8=(%d)\n",len,KEY_LENGTH/8);
        return -1;
    }

    printf("len:%d, data:%s\n",len,buf);
    //PRINT_HEX(buf, len);

    int c_len;
    start   = clock();
    for (j = 0; j < loop; j++)
        encrypt(buf, len, key_n, n_len, key_e, e_len, cipher, &c_len);
    end = clock();
    tt = (double) (end - start) / CLOCKS_PER_SEC;
    printf("encrypt speed:%lf ms\n", (double) 1000 * tt/j);
    
    printf("len:%d, cipher data:\n", c_len);
    //PRINT_HEX(cipher, c_len);

    start   = clock();
    for (j = 0; j < loop; j++)
        decrypt(cipher, c_len, key_n, n_len, key_d, d_len, plain);
    end = clock();
    tt = (double) (end - start) / CLOCKS_PER_SEC;
    printf("decrypt speed:%lf ms\n", (double) 1000 * tt/j);
    printf("len:%zd, plain data:%s\n",strlen(plain),plain);
    //PRINT_HEX(plain, strlen(plain));
      
    if(strcmp(buf, plain) != 0)  
        printf("\n----------------\noops! decrypt failed!!!!!!\n----------------\n\n");  
    else  
        printf("\n----------------\ncongratulations! decrypt OK.\n----------------\n\n");  
  
    return 0;  
}  

#endif

