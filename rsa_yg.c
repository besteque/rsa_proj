#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <gmp.h>

#include "rsa_yg.h"
  

#define BASE 62    //输入输出的数字进制,62=sum(0-9,A-Z,a-z)，但未包含符号

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


  
//生成两个大素数
mpz_t * gen_primes(int nbits, mpz_t p, mpz_t q)  
{    
    mpz_t key_p, key_q;
    gmp_randstate_t grt;
    
    gmp_randinit_default(grt);
    gmp_randseed_ui(grt, time(NULL));
      
    mpz_init(key_p);  
    mpz_init(key_q);  
  
    mpz_urandomb(key_p, grt, nbits / 2);         
    mpz_urandomb(key_q, grt, nbits / 2);   //随机生成两个大整数  
  
    mpz_init(p);
    mpz_init(q);
  
    mpz_nextprime(p, key_p);  //使用GMP自带的素数生成函数
    mpz_nextprime(q, key_q);  
  
    mpz_clear(key_p);  
    mpz_clear(key_q);  
  
    return 0;    
}  


/**
 * nbits means prime bit len
*/
int generate_key(int nbits, char *n, char *e, char *d)
{  
    gmp_randstate_t grt;
    mpz_t p, q, key_n, key_e, key_fn, gcd; 
    char *buf_fn = NULL;
    char *buf_n = NULL;
    char *buf_e = NULL;
    char *buf_d = NULL;

    buf_fn = calloc(1, nbits+10);
    buf_n = calloc(1, nbits+10);
    buf_e = calloc(1, nbits+10);
    buf_d = calloc(1, nbits+10);
    
    gmp_randinit_default(grt);    
    gmp_randseed_ui(grt, time(NULL)); 
    
    gen_primes(nbits, p, q);  
  
    mpz_init(key_n);  
    mpz_init(key_fn);  
  
    mpz_mul(key_n, p, q);       //计算n=p*q  
    mpz_sub_ui(p, p, 1);        //p=p-1  
    mpz_sub_ui(q, q, 1);        //q=q-1  
    mpz_mul(key_fn, p, q);       //计算欧拉函数φ(n)=(p-1)*(q-1)  
    
    do
    {  
        mpz_urandomm(key_e, grt, key_fn);
        mpz_gcd(gcd,key_e,key_fn);   //set e
    }while(mpz_get_ui(gcd)!=1);

    //gmp_printf ("key_e:%Zd\n", key_e);
    mpz_get_str(buf_e, BASE, key_e);
    mpz_get_str(buf_fn, BASE, key_fn);
    //gmp_printf ("key_fn:%Zd\n", key_fn);
    //printf("buf_e:%s\n", buf_e);
    //printf("buf_fn:%s\n", buf_fn);
    
    mpz_t key_d;      
    mpz_init(key_d);  

    // mpz_invert(rop, op1, op2)  ，op1*rop ≡ 1 (mod op2)暗示 (op1*rop - 1) mod op2 = 0
    mpz_invert(key_d, key_e, key_fn);   //计算数论倒数  
  
    mpz_get_str(buf_n, BASE, key_n);  
    strcpy(n, buf_n); 
    
    mpz_get_str(buf_d, BASE, key_d);
    strcpy(d, buf_d); 
    
    mpz_get_str(buf_e, BASE, key_e);
    strcpy(e, buf_e);  

    //释放内存
    mpz_clear(p);
    mpz_clear(q);  
    mpz_clear(key_n);
    mpz_clear(key_d);
    mpz_clear(key_e);
    mpz_clear(key_fn);

    free(buf_fn);
    free(buf_n);
    free(buf_e);
    free(buf_d);
  
    return 0;  
}


//加密函数  
int encrypt(const char * plain_text, const int p_len, const char * key_n, const char *key_e, char *cipher)
{
    int i,j = 0;
    mpz_t M, C, n, e;
    char *data = NULL;

    data = calloc(1, p_len*2);


    // asc值转字符串，长度放大一倍
    for (i = 0; i < p_len; i++)
    {
        j += sprintf(data+j, "%02X", plain_text[i]);
    }
    
    mpz_init_set_str(M, data, BASE);   
    mpz_init_set_str(n, key_n, BASE);  
    mpz_init_set_str(e, key_e, BASE);  
    mpz_init_set_ui(C, 0);  
  
    //mpz_powm_ui(C, M, key_e, n);    //使用GMP中模幂计算函数
    mpz_powm(C, M, e, n);    //使用GMP中模幂计算函数
  
    mpz_get_str(cipher, BASE, C);

    free(data);
  
    return 0;  
}  
  
//解密函数  
int decrypt(const char * cipher_text, const int c_len, const char * key_n, const char * key_d, char *plain)
{  
    int i,j = 0;
    mpz_t M, C, n, d; 
    char swap[3] = {0};
    int p_len;
    char *pseudo = NULL;
    
    mpz_init_set_str(C, cipher_text, BASE);   
    mpz_init_set_str(n, key_n, BASE);  
    mpz_init_set_str(d, key_d, BASE);  
    mpz_init(M);  
  
    mpz_powm(M, C, d, n);   //使用GMP中的模幂计算函数  

    pseudo = calloc(1, c_len);
    mpz_get_str(pseudo, BASE, M); 

    p_len = (strlen(pseudo)+1)/2;
    
    for (i = 0; i < p_len; i++)
    {
        memcpy(swap, &pseudo[i*2], 2); 
        plain[j] = strtol(swap, 0, 16);
        j++;
    }

    free(pseudo);
  
    return 0;  
}  
 

#if 0
// gcc -g -O2 -o demo rsa_test.c -lgmp 
int test_rsa()  
{ 
    int i,j = 0, len;
    key_pair * p = gen_key_pair();

    //setKey(1024, 17);
    //printf("------------------over----------------\n");

    
  
    printf("n = %s\n", p->n); 
    printf("d = %s\n", p->d);
    printf("e = %s\n", p->e);

    printf("\n----------------------------------->\n");
    printf("public key(n,e):%s,%s\n", p->n, p->e);
    printf("private key(n,d):%s,%s\n", p->n, p->d);
    printf("<-----------------------------------\n\n");
  
    char buf[KEY_LENGTH + 10];  
    char data[KEY_LENGTH + 10];  
    char tmp[KEY_LENGTH + 10];  
    char swap[3] = {0};
    printf("请输入要加密的数字，二进制长度不超过%d\n",KEY_LENGTH); 
    //scanf("%s", buf);
    strcpy(buf, "./lk0cU-9C083GBFJB/KN V 8989WOH2KLN2W   P ");

    len = strlen(buf);
    printf("input msg len:%d\n",len); 


    // asc值转字符串，长度放大一倍
    for (i = 0; i < len; i++)
    {
        j += sprintf(data+j, "%02X", buf[i]);
    }
    printf("len:%zd data:%s\n",strlen(data), data); 
    //end asc值转字符串


    // 字符串转回asc值
    j = 0;
    for (i = 0; i < len; i++)
    {
        memcpy(swap, &data[i*2], 2);

        //printf("swap[%d] %s:\n", i*2, swap); 
    
        tmp[j] = strtol(swap, 0, 16);
        //printf("tmp[%d] %d:\n", j, tmp[j]); 
        j++;
    }
    printf("true data as follow:\n"); 
    PRINT_HEX(tmp, len);
    //end 字符串转回asc值


    
    char *cipher_text;
    cipher_text = encrypt(data, p->n, p->e);  
    printf("密文为：%s\n",cipher_text);  
    
    char *plain_text;
    int p_len;
    char true_data[1024] = {0};
    plain_text = decrypt(cipher_text, p->n, p->d);  
    //printf("明文为：%s\n",plain_text);


    p_len = strlen(plain_text);
    j = 0;
    for (i = 0; i < p_len/2; i++)
    {
        memcpy(swap, &plain_text[i*2], 2);

        //printf("swap[%d] %s:\n", i*2, swap); 
    
        true_data[j] = strtol(swap, 0, 16);
        //printf("tmp[%d] %d:\n", j, true_data[j]); 
        j++;
    }
    printf("明文为：%s\n",true_data);
    
      
    if(strcmp(buf, true_data) != 0)  
        printf("无法解密\n");  
    else  
        printf("解密成功\n");  
  
    return 0;  
}  

#endif

