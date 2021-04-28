#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

int main(void) {

	// Create the console bio.
	BIO *bio_console = BIO_new(BIO_s_file());
	BIO_set_fp(bio_console, stdout, BIO_NOCLOSE);

	// Bignum exponent for the RSA private key generation.
	BIGNUM *e = BN_new();
	BN_set_word(e, RSA_F4);

	RSA *rsa = RSA_new();
	RSA_generate_key_ex(rsa, 1024, e, NULL);

	PEM_write_bio_RSAPrivateKey(bio_console, rsa, NULL, NULL, 0, NULL, NULL);
	return 0;
}
