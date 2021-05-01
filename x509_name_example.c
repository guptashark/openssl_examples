#include <openssl/ssl.h>
#include <openssl/err.h>

void InitX509Name(X509_NAME *x_name);

int main(void) {

	// Create the console bio.
	BIO *bio_console = BIO_new(BIO_s_file());
	BIO_set_fp(bio_console, stdout, BIO_NOCLOSE);

	X509_NAME *x_name = X509_NAME_new();
	InitX509Name(x_name);
	X509_NAME_print(bio_console, x_name, 0);
	BIO_printf(bio_console, "\n");

	return 0;
}


void InitX509Name(X509_NAME *x_name) {

	// The ones we see:
	// countryName: C
	// stateOrProvinceName: ST
	// localityName: L
	// organizationName: O
	// organizationalUnitName: OU
	// commonName: (FQDN or YOUR name): CN
	// emailAddress:

	X509_NAME_add_entry_by_txt(
		x_name, "countryName", MBSTRING_ASC,
		"US", -1, -1, 0);

	X509_NAME_add_entry_by_txt(
		x_name, "stateOrProvinceName", MBSTRING_ASC,
		"MI", -1, -1, 0);

	X509_NAME_add_entry_by_txt(
		x_name, "localityName", MBSTRING_ASC,
		"Detroit", -1, -1, 0);

	X509_NAME_add_entry_by_txt(
		x_name, "organizationName", MBSTRING_ASC,
		"Schneider", -1, -1, 0);

	X509_NAME_add_entry_by_txt(
		x_name, "commonName", MBSTRING_ASC,
		"Ash Gupta", -1, -1, 0);

	X509_NAME_add_entry_by_txt(
		x_name, "organizationalUnitName", MBSTRING_ASC,
		"Unit", -1, -1, 0);

	X509_NAME_add_entry_by_txt(
		x_name, "emailAddress", MBSTRING_ASC,
		"guptashark@protonmail.com", -1, -1, 0);
}
