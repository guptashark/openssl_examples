#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

void InitX509Name(X509_NAME *x_name);

int main(void) {

	// Create the console bio.
	BIO *bio_console = BIO_new(BIO_s_file());
	BIO_set_fp(bio_console, stdout, BIO_NOCLOSE);


	// read the rsa private key into an EVP_PKEY.
	FILE *rsa_key_file = fopen("sample.pem", "r");
	RSA *rsa = PEM_read_RSAPrivateKey(rsa_key_file, NULL, 0, NULL);

	EVP_PKEY *p_key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(p_key, rsa);

	// Create an X509_REQ
	X509_REQ *x_req = X509_REQ_new();

	{
		long version = 0;
		X509_REQ_set_version(x_req, version);
	}

	// get the X509_NAME, set the distinguished name fields.
	// (this fn gives us an internal pointer.
	X509_NAME *x_name = X509_REQ_get_subject_name(x_req);
	InitX509Name(x_name);


	X509_ALGOR *sign_algo = X509_ALGOR_new();
	X509_ALGOR_set0(
		sign_algo, OBJ_nid2obj(NID_sha256WithRSAEncryption),
		V_ASN1_UNDEF, NULL);

	X509_REQ_set1_signature_algo(x_req, sign_algo);

	// set the key in the X509_REQ
	X509_REQ_set_pubkey(x_req, p_key);

	// sign our certificate request
	X509_REQ_sign(x_req, p_key, EVP_sha256());

	// write the certificate to a file.
	FILE *x509_req_file = fopen("prog_gen.csr", "w");
	PEM_write_X509_REQ(x509_req_file, x_req);
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
		x_name, "organizationalUnitName", MBSTRING_ASC,
		"Unit", -1, -1, 0);

	X509_NAME_add_entry_by_txt(
		x_name, "commonName", MBSTRING_ASC,
		"Ash Gupta", -1, -1, 0);


	X509_NAME_add_entry_by_txt(
		x_name, "emailAddress", MBSTRING_ASC,
		"guptashark@protonmail.com", -1, -1, 0);
}
