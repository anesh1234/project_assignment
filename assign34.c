#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char * msg, BIGNUM * a)
{
    // Use BN_bn2hex(a) for hex string
    // Use BN_bn2dec(a) for decimal string
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}


int main ()
{
	// Setup; the variables needed
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *n = BN_new();
	BN_hex2bn(&n,"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	
	BIGNUM *e = BN_new();
        BN_hex2bn(&e,"010001");
	
	BIGNUM *d = BN_new();
        BN_hex2bn(&d,"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	
	BIGNUM *s = BN_new();
	BIGNUM *s2 = BN_new();

	// m = "I owe you $2000." Translated to hex is "49206F776520796F752024323030302E"
	// m2 = "I owe you $3000." Translated to hex is "49206F776520796F752024333030302E"
	
	BIGNUM *m = BN_new();
	BN_hex2bn(&m,"49206F776520796F752024323030302E");
	BIGNUM *m2 = BN_new();
        BN_hex2bn(&m2,"49206F776520796F752024333030302E");
	
	char *msg1 = "The original m in hex is: ";
	printBN(msg1, m);
	char *msg2 = "The original m2 in hex is: ";
        printBN(msg2, m2);

	// Signing the messages
	BN_mod_exp(s, m, d, n, ctx);
	BN_mod_exp(s2, m2, d, n, ctx);

	char *msg3 = "The signature of m is: ";
        printBN(msg3, s);
	char *msg4 = "The signature of m2 is: ";
        printBN(msg4, s2);

    return 0;

}
 
