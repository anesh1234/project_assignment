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
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *p = BN_new();
	BN_hex2bn(&p,"F7E75FDC469067FFDC4E847C51F452DF");
	BIGNUM *q = BN_new();
	BN_hex2bn(&q,"E85CED54AF57E53E092113E62F436F4F");
	BIGNUM *e = BN_new();
	BN_hex2bn(&e,"0D88C3");
	BIGNUM *n = BN_new();
	BN_mul(n, p, q, ctx);

	BIGNUM *phiN = BN_new();
	BIGNUM *p2 = BN_new();
	BIGNUM *q2 = BN_new();
	BIGNUM *a = BN_new();
	BN_dec2bn(&a, "1");
	BN_sub(p2, p, a);
	BN_sub(q2, q, a);
	BN_mul(phiN, p2, q2, ctx);

	// The formula for the private key is d ≡ e^(−1) (mod phi(n))
	BIGNUM *d = BN_new();
	BN_mod_inverse(d, e, phiN, ctx);
	char* m = "The private key, d is: ";
	printBN(m,d);

    return 0;

}
 
