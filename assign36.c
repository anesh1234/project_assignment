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

		// The CA's public key modulus
	BIGNUM *n = BN_new();
	BN_hex2bn(&n,"B77FA55928F2FB8CE3BE537F8E4757705B0A5FC1F49CBCF46D4246416370F634E9603D952FBB7566D403B1AD5942A892CAFAF6128CC1C32C369C65C3B6F78DE5C5831074F7F9E66A57005AD9CBCC5F8B6832840390D09AF2B3BA1D677C87EA1222824129975E1D3D5ECF9D3BB726E6A6DA2F686134909201E8DC8B072F38580536010C478DB09BA288147B105B6F23840FB5BBF334A7A7D5C117AE12065F2DF771F363F1D0B25C9379524F7101FC97DB76C74ECF3CE0E58918D5D7EEA9FF32E5F51E67B0B35976D38EE8F05FF4E8BE6796280DFA54B0B3EF96B35BAB4336E0E7EBA14EA400D967DA2655A17A06A34988B31597A3F7FDCD0E894302E99E4E7CA7");
	
		// The certificate ISSUER's public key exponent

	BIGNUM *ipk = BN_new();
        BN_dec2bn(&ipk,"65537");
	
		// The signaure on the certificate
	BIGNUM *s = BN_new();
	BN_hex2bn(&s, "4fae2d9edaef16d21f19ffc710a1ea17946606725ead7200b13c8e1b1ab9b11d2123a21272348a5e7a3ff9ef57201c371feec23c746884e1772ed137e931b5e2702881b535e258f3dba00fa14bcc923e01fa4fdbc8879d526e47bd0c5aca926908497609a3c8e1f8b7a0e85f7cc0727fd616d4210971cfa7bcba7e1ad6e5965dbfc4743c0df2423412d3c6f8e5abda8ceb6ac86b4157692ac16760bf2a850f8c896265307b4199c369b0cdb7dc34f6587c8f10d15e07c27f7054953742b69230ceb357aa9678bab2bdb4ed6ff67d7b61284dcd82d6afd6ae5f34694ab2614d8b99e166af1e5b1121abecfc81db7862a762a45535e6e24a1089e30ebdd5b48bc3");

		// The hash of the certificate's body

	BIGNUM *certHash = BN_new();
 	BN_hex2bn(&certHash,"a1cd962d4764788dd2708fc5a164b45ec0b3221b98c7adff73e22e8db48aa828");
	
	// Verification of the signature

	BIGNUM *res = BN_new();
	BN_mod_exp(res, s, ipk, n, ctx);
	
	char *msg1 = "The signature to the power of the issuer's public key is: ";
        printBN(msg1, res);
	
	char *msg2 = "The certificate hash is: ";
        printBN(msg2, certHash);

	
	if (res == certHash){
		char *msg2 = "The signature to the power of the issuer's public key is equal to the certificate hash.";
		printf("%s", msg2);
	}
	else {
		char *msg2 = "The signature to the power of the issuer's public key is NOT equal to the certificate hash.";
		printf("%s", msg2);
	}

    return 0;

}
