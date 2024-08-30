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
	BN_hex2bn(&n,"AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	
	BIGNUM *e = BN_new();
        BN_hex2bn(&e,"010001");

	BIGNUM *res1 = BN_new();
	BIGNUM *res2 = BN_new();
	
	// The signatures received from Alice. s1 is the complete one, s2 is the corrupted one
	
	BIGNUM *s1 = BN_new();
	BN_hex2bn(&s1,"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	BIGNUM *s2 = BN_new();
        BN_hex2bn(&s2,"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

	// Verification of the signatures

	BN_mod_exp(res1, s1, e, n, ctx);
	char *msg1 = "The complete signature to the power of Alice's public key is ";
        printBN(msg1, res1);

	BN_mod_exp(res2, s2, e, n, ctx);
	char *msg2 = "The corrupt signature to the power of Alice's public key is ";
        printBN(msg2, res2);

    return 0;

}
