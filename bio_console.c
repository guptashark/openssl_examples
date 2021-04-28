#include <openssl/bio.h>

int main(void) {
	BIO *bio_console = BIO_new(BIO_s_file());
	BIO_set_fp(bio_console, stdout, BIO_NOCLOSE);
	BIO_printf(bio_console, "OpenSSL bio_console\n");
	return 0;
}
