#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <gmp.h>  
  
#define KEY_LENGTH 2048  //公钥的长度
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


typedef struct tag_key_pair  
{  
    char n[KEY_LENGTH + 10]; 
    char d[KEY_LENGTH + 10];  
    int e;  
}key_pair;  

#define PRINT_HEX(d, l)\
        do\
        {\
            int i;\
            for(i=0;i<l;i++)\
            {\
                if((i+1) % 16) \
                    printf("%02X ", (unsigned char)d[i]); \
                else if (i == l-1)\
                    printf("%02X\n", (unsigned char)d[i]); \
                else\
                    printf("%02X\n", (unsigned char)d[i]);\
            }\
            if(i % 16) printf("\n");\
        }\
        while(0)

  
//生成两个大素数
mpz_t * gen_primes()  
{                                         
    gmp_randstate_t grt;                  
    gmp_randinit_default(grt);    
    gmp_randseed_ui(grt, time(NULL));     
      
    mpz_t key_p, key_q;  
    mpz_init(key_p);  
    mpz_init(key_q);  
  
    mpz_urandomb(key_p, grt, KEY_LENGTH / 2);         
    mpz_urandomb(key_q, grt, KEY_LENGTH / 2);   //随机生成两个大整数  
  
    mpz_t *result;  
    result = malloc(sizeof(mpz_t)*2);
    bzero(result, sizeof(mpz_t)*2);
    mpz_init(result[0]);  
    mpz_init(result[1]);  
  
    mpz_nextprime(result[0], key_p);  //使用GMP自带的素数生成函数
    mpz_nextprime(result[1], key_q);  
  
    mpz_clear(key_p);  
    mpz_clear(key_q);  
  
    return result;    
}  

//生成密钥对
key_pair * gen_key_pair()  
{  
    mpz_t * primes = gen_primes();  
  
    mpz_t key_n, key_e, key_f;  
    mpz_init(key_n);  
    mpz_init(key_f);  
    mpz_init_set_ui(key_e, 65537);  //设置e为65537  
  
    mpz_mul(key_n, primes[0], primes[1]);       //计算n=p*q  
    mpz_sub_ui(primes[0], primes[0], 1);        //p=p-1  
    mpz_sub_ui(primes[1], primes[1], 1);        //q=q-1  
    mpz_mul(key_f, primes[0], primes[1]);       //计算欧拉函数φ(n)=(p-1)*(q-1)  
  
    mpz_t key_d;      
    mpz_init(key_d);  

    // mpz_invert(rop, op1, op2)  ，op1*rop ≡ 1 (mod op2)暗示 (op1*rop - 1) mod op2 = 0
    mpz_invert(key_d, key_e, key_f);   //计算数论倒数   
  
    key_pair *result = malloc(sizeof(key_pair)); 
    bzero(result, sizeof(key_pair));
  
    char buf_n[KEY_LENGTH + 10] = {0};  
    char buf_d[KEY_LENGTH + 10] = {0};  
  
    mpz_get_str(buf_n, BASE, key_n);  
    memcpy(result->n, buf_n, KEY_LENGTH + 10);  
    mpz_get_str(buf_d, BASE, key_d);  
    memcpy(result->d, buf_d, KEY_LENGTH + 10);  
    result->e = 65537;  
  
    mpz_clear(primes[0]);   //释放内存  
    mpz_clear(primes[1]);  
    mpz_clear(key_n);  
    mpz_clear(key_d);  
    mpz_clear(key_e);  
    mpz_clear(key_f);  
    
    free((char*)primes);  
  
    return result;  
} 

#if 0 //cpp
void setKey(mpz_class &n, mpz_class &e, mpz_class &d,const int nbits,int ebits=16)  
{  
    if(nbits/2<=ebits) {  
        ebits = nbits/2;  
    }  
    mpz_class p = randprime(nbits/2);  
    mpz_class q = randprime(nbits/2);  
    n = q*p;  
    mpz_class fn = (p-1)*(q-1);  
    mpz_class gcd;  
    do{  
        e = randprime(ebits);  
        mpz_gcd(gcd.get_mpz_t(),e.get_mpz_t(),fn.get_mpz_t());  
    }while(gcd!=1);  
    mpz_gcdext(p.get_mpz_t(),d.get_mpz_t(),q.get_mpz_t(),e.get_mpz_t(),fn.get_mpz_t());  
}  

#endif

//加密函数  
char * encrypt(const char * plain_text, const char * key_n, int key_e)    
{  
    mpz_t M, C, n;  
    mpz_init_set_str(M, plain_text, BASE);   
    mpz_init_set_str(n, key_n, BASE);  
    mpz_init_set_ui(C, 0);  
  
    mpz_powm_ui(C, M, key_e, n);    //使用GMP中模幂计算函数
  
    char *result = calloc(1, KEY_LENGTH + 10);  
    mpz_get_str(result, BASE, C);  
  
    return result;  
}  
  
//解密函数  
char * decrypt(const char * cipher_text, const char * key_n, const char * key_d)    
{  
    mpz_t M, C, n, d;  
    mpz_init_set_str(C, cipher_text, BASE);   
    mpz_init_set_str(n, key_n, BASE);  
    mpz_init_set_str(d, key_d, BASE);  
    mpz_init(M);  
  
    mpz_powm(M, C, d, n);   //使用GMP中的模幂计算函数  
  
    char *result = calloc(1, KEY_LENGTH + 10); 
    mpz_get_str(result, BASE, M);  
  
    return result;  
}  
 

// gcc -g -O2 -o demo rsa_test.c -lgmp 
int main()  
{ 
    int i,j = 0, len;
    key_pair * p = gen_key_pair();  
  
    printf("n = %s\n", p->n); 
    printf("d = %s\n", p->d);
    printf("e = %d\n", p->e);

    printf("\n----------------------------------->\n");
    printf("public key(n,e):%s,%x\n", p->n, p->e);
    printf("private key(n,d):%s,%s\n", p->n, p->d);
    printf("<-----------------------------------\n\n");
  
    char buf[KEY_LENGTH + 10];  
    char data[KEY_LENGTH + 10];  
    char tmp[KEY_LENGTH + 10];  
    char swap[3] = {0};
    printf("请输入要加密的数字，二进制长度不超过%d\n",KEY_LENGTH); 
    scanf("%s", buf);
    //strcpy(buf, "./lk0cU-9C083GBFJB/KN V 8989WOH2KLN2W   P ");

    len = strlen(buf);
    printf("input msg len:%d\n",len); 


    // asc值转字符串，长度放大一倍
    for (i = 0; i < len; i++)
    {
        j += sprintf(data+j, "%02X", buf[i]);
    }
    printf("len:%zd data:%s\n",strlen(data), data); 
    //end asc值转字符串


    // 字符串转会asc值
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
    //end 字符串转会asc值


    
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


