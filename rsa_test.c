#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rsa_yg.h"
  
#define KEY_LENGTH 2048  //公钥的长度

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

 

// gcc -g -O2 -o demo rsa_test.c rsa_yg.c -lgmp
//or
//gcc -c rsa_yg.c -o rsa_yg.o;cp libgmp.a librsa.a;gcc -g -O2 -o demo rsa_test.c -L. -lrsa 
int main()  
{ 
    int i,j = 0, len;
    char key_n[KEY_LENGTH + 10] = {0};
    char key_e[KEY_LENGTH + 10] = {0};
    char key_d[KEY_LENGTH + 10] = {0};
    char buf[KEY_LENGTH + 10] = {0};
    char cipher[KEY_LENGTH + 10] = {0};
    char plain[KEY_LENGTH + 10] = {0};

    generate_key(2048, key_n, key_e, key_d);
    printf("n = %s\n", key_n); 
    printf("e = %s\n", key_e);
    printf("d = %s\n", key_d);
  
    printf("请输入要加密的数字，二进制长度不超过%d\n",KEY_LENGTH); 
    //scanf("%s", buf);
    //strcpy(buf, "0\\0./lk0cU-9C083GBFJB/KN V 8989WOH2KLN2W   P ");
    strcpy(buf, "0\\0./lk0cU-9C083GBFJB/KN V 8989WOH2KLN2W   P 0\\0./lN V 8989WOH2KLNN V 8989WOH2KLNN V 8989WOH2KLNk0cU-9C083GBFJB/KN V 8989WOH2KLN2W   P 0\\0./lk0cU89WOH2KLN2W   P 0\\0./lk0cU89WOH2KLN2W   P 0\\0./lk0cU89WOH2KLN2W   P 0\\0./lk0cU89WOH2KLN2W   P 0\\0./lk0cU");

    len = strlen(buf);

    printf("len:%d, 原文为：%s\n",len,buf);

    encrypt(buf, len, key_n, key_e, cipher);
    printf("len:%zd, 密文为：%s\n",strlen(cipher),cipher);

    len = strlen(cipher);
    decrypt(cipher, len, key_n, key_d, plain);
    printf("len:%zd, 明文为：%s\n",strlen(plain),plain);    
      
    if(strcmp(buf, plain) != 0)  
        printf("无法解密\n");  
    else  
        printf("解密成功\n");  
  
    return 0;  
}  


