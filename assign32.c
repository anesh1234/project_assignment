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
	
	BIGNUM *M = BN_new();
	BN_hex2bn(&M,"4120746f702073656372657421");
	
	BIGNUM *c = BN_new();
	BIGNUM *dc = BN_new();

	// Encrypting the message M with the public key (e, n)
	// The RSA formula for encryption is c = m^e (mod n), where c is the cipher text and e is the public key
	BN_mod_exp(c, M, e, n, ctx);
	char *msg = "The cipher text is: ";
	printBN(msg, c);

	// The RSA formula for decryption is c^d, where c is the cipher text and d is the private key
	BN_mod_exp(dc, c, d, n, ctx);
	char *msg2 = "The deciffered cipher text is: ";
        printBN(msg2, dc);

    return 0;

}
 
