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
// or
// gcc -c rsa_yg.c -o rsa_yg.o;cp libgmp.a librsa.a;gcc -g -O2 -o demo rsa_test.c -L. -lrsa 
int main()  
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


