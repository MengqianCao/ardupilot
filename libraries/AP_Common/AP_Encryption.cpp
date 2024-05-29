#include "AP_Encryption.h"
#include <AP_Logger/AP_Logger.h>
#include <time.h>

static const char base64_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '+', '/'};

void base64encode(char* encodeing_str,uint8_t* a,uint8_t len) {
    char tmp[64]={'\0'};
    uint8_t round = len/3;
    uint8_t flag=len%3;
    uint8_t i;
    for (i=0;i<round;i++){
        tmp[i*4] = base64_alphabet[((a[i*3]&252) >> 2)];
        tmp[i*4+1] = base64_alphabet[((a[i*3]&3) << 4) + ((a[i*3+1]&240) >> 4)];
        tmp[i*4+2] = base64_alphabet[((a[i*3+1]&15) << 2) + ((a[i*3+2]&192) >> 6) ];
        tmp[i*4+3] = base64_alphabet[a[i*3+2]&63];
    }
    
    if (flag == 1){
        tmp[i*4] = base64_alphabet[((a[i*3]&252) >> 2)];
        tmp[i*4+1] = base64_alphabet[((a[i*3] & 3) << 4)];
        tmp[i*4+2] = '=';
        tmp[i*4+3] = '=';
    }

    if (flag == 2){
        tmp[i*4] = base64_alphabet[((a[i*3]&252) >> 2)];
        tmp[i*4+1] = base64_alphabet[((a[i*3]&3) << 4) + ((a[i*3+1]&240) >> 4)];
        tmp[i*4+2] = base64_alphabet[((a[i*3+1]&15) << 2)];
        tmp[i*4+3] = '=';       
    }
    memcpy(encodeing_str,tmp,sizeof(tmp));     
}

uint8_t s_box[256];
uint8_t t_box[256];
uint8_t keystream[256];
uint8_t key[16];
uint8_t key_rsa[32];

uint16_t modulus=6319;
uint16_t publicExponent=37;

uint16_t fastExpMod(uint16_t a,uint16_t b,uint16_t c) {
    uint32_t ans=1;
    uint32_t base=a%c;
    while(b){
        if(b&1)
        ans=(ans*base)%c;
        base=(base*base)%c;
        b>>=1;
    }
    return ans;
}

void rc4_init(){
    uint8_t temp,t,j;
    uint16_t i;
    //init 128bit key
    srand((uint32_t)time(NULL));
    for (i=0;i<16;i++){
        temp=rand()%256;
        key[i]=temp;
    }
    uint32_t tmp;

    //RSA encrtpt 
    for (i=0;i<16;i++){
        tmp=fastExpMod(key[i],publicExponent,modulus);
        key_rsa[i*2]=tmp/256;
        key_rsa[i*2+1]=tmp%256;
    }
    
    //init s_box & t_box
    for (i=0;i<256;i++){
        s_box[i]=i;
        temp = key [i%16];
        t_box[i]=temp;
    } 
    //swap s_box
    j=0;
    for(i=0;i<256;i++){
        j=(j+s_box[i]+t_box[i])%256;
        temp=s_box[i];
        s_box[i]=s_box[j];
        s_box[j]=temp;
    }
    //get keystream
    j=0;t=0;
    for (i=0;i<256;i++){
        i=i%256;
        j=(j+s_box[i])%256;
        temp=s_box[i];
        s_box[i]=s_box[j];
        s_box[j]=temp;
        t=(s_box[i]+s_box[j])%256;
        keystream[i]=s_box[t];
    }
    //write key to log
    struct log_Key pkt {
        LOG_PACKET_HEADER_INIT(LOG_KEY_MSG),
        key:{}
    };
    char key_str[64]={'\0'};  
    base64encode(key_str,key_rsa,32);
    memcpy(pkt.key,key_str,sizeof(key_str));
    AP::logger().WriteBlock(&pkt, sizeof(pkt));
}

void rc4_encrypt(char* crypto_text, int32_t data){
    char text[64]={"\0"};
    int_to_char(data,text);
    uint8_t i;
    uint8_t tmp[64];
    for(i=0;i<strlen(text);i++){
        tmp[i]=text[i]^keystream[i];
    }
    base64encode(crypto_text,tmp,strlen(text));
}

void rc4_encrypt(char* crypto_text, char* data){
    char text[64]={"\0"};
    memcpy(text,data,64);
    uint8_t i;
    uint8_t tmp[64];
    for(i=0;i<strlen(text);i++){
        tmp[i]=text[i]^keystream[i];
    }
    base64encode(crypto_text,tmp,strlen(text));
}