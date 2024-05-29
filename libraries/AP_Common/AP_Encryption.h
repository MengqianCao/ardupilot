#include <AP_Common/AP_Common.h>
#include <AP_Logger/AP_Logger.h> 
#include <string.h>
#include <stdlib.h>
#include <time.h>

void base64encode(char* encodeing_str,uint8_t* a,uint8_t len);
void rc4_init();
void rc4_encrypt(char* crypto_text, int32_t data);
void rc4_encrypt(char* crypto_text, char* data);