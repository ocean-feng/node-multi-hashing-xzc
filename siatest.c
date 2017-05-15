#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sia.h"

void bin2hex(char *s, const unsigned char *p, size_t len)
{
	for (int i = 0; i < len; i++)
		sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);
}

char *abin2hex(const unsigned char *p, size_t len)
{
	char *s = (char*) malloc((len * 2) + 1);
	if (!s)
		return NULL;
	bin2hex(s, p, len);
	return s;
}

int hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
	char hex_byte[3];
	char *ep;

	hex_byte[2] = '\0';

	while (*hexstr && len) {
		if (!hexstr[1]) {
			return 0;
		}
		hex_byte[0] = hexstr[0];
		hex_byte[1] = hexstr[1];
		*p = (unsigned char) strtol(hex_byte, &ep, 16);
		if (*ep) {
			return 0;
		}
		p++;
		hexstr += 2;
		len--;
	}

	return(!len) ? 1 : 0;
/*	return (len == 0 && *hexstr == 0) ? true : false; */
}

//gcc -std=c99 -o siatest siatest.c sia.c crypto/blake2b.c -I./sha3
int main(int argc, char* argv[]){
	char input[65] = {0};
	char hash[32] = {0};
	input[0] = 1;

	char *hexinput = "0d8a2ae98f16d28220e80bfd94f13ee8f02b708bd9eaf9706778f7a319a6c5d9ae552cfdb292d0793133b61b50977295ad602d0f6623db93c9f7cf0c8fca59eb";
	hex2bin(input+1, hexinput, 64);
	sia_hash(input, hash, 65);
	char *hash_hex = abin2hex(hash, 32);
	printf("test**************** hash_hex = %s\n", hash_hex);
	free(hash_hex);
	return 0;
}