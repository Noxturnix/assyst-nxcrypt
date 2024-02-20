#include <emscripten/bind.h>
#include <iomanip>
#include <sstream>

#include "sodium/crypto_generichash.h"
#include "sodium/crypto_secretbox.h"
#include "sodium/utils.h"

using namespace emscripten;
using namespace std;

string LowerString(string const &str) {
	string nStr(str);
	for (char &c : nStr)
		c = tolower(c);
	return nStr;
}

// For debugging.
string BufferToHex(unsigned char *buf, size_t size) {
	ostringstream oss;
	oss << hex << setfill('0');
	for (unsigned int i = 0; i < size; ++i)
		oss << setw(2) << static_cast<unsigned int>(buf[i]);
	return oss.str();
}

string run(vector<string> const &args) {
	if (args.size() != 2)
		return "## Usage: `-t nxdecrypt [<password>/--nopassword] <ciphertext>`\nAdvanced text decryption program running directly on Assyst's sandbox environment via WebAssembly.\n\nExample:\n- `-t nxdecrypt 123456 JWjHUkfEW8zIatVt2wzdnbwncK8d22dEEbsxz694lN+oV4u0etCo+vdnW9/b3Ho6s7BkcNd1pq/rt6mdLkfbSD5qh3SNyte8`\n- `-t nxdecrypt --nopassword kDISVxM6xFWrNTt9J8Esx4Xeq7C8K8uoegSm+BgECi5mTvhqCCy6Bd0sbYi0feVgVfwOOrZKanE=`\n\nNote:\nUse `-t nxencrypt` to encrypt a message.";

	ostringstream outputOSS;

	string encrypted_base64(args.at(1));
	string password(args.at(0));
	unsigned char key_key[crypto_generichash_KEYBYTES] = { 0xed, 0x15, 0x73, 0x95, 0xa4, 0xd1, 0x05, 0xbc, 0xca, 0x36, 0x1f, 0x4e, 0xde, 0x64, 0x78, 0x5c, 0x88, 0xb4, 0x27, 0x44, 0xcb, 0x67, 0xe3, 0x19, 0xf9, 0x58, 0x2f, 0xbe, 0xbc, 0xea, 0x0f, 0xc9 }; // blake2b-256("Noxturnix")
	unsigned char key[crypto_secretbox_KEYBYTES];
	unsigned char nonce[crypto_secretbox_NONCEBYTES];

	if (LowerString(password) == "--nopassword")
		password.clear();

	// Base64 decode.
	unsigned char encrypted[encrypted_base64.length() * 2];
	size_t encrypted_size;
	if (sodium_base642bin(encrypted, sizeof encrypted, encrypted_base64.c_str(), encrypted_base64.length(), NULL, &encrypted_size, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) return "Failed to decode ciphertext.";

	// Extract nonce.
	unsigned char ciphertext[encrypted_size - crypto_secretbox_NONCEBYTES];
	for (unsigned int i = sizeof ciphertext; i < encrypted_size; ++i) nonce[i - sizeof ciphertext] = encrypted[i];
	for (unsigned int i = 0; i < sizeof ciphertext; ++i) ciphertext[i] = encrypted[i];

	// Hash the password.
	crypto_generichash(key, sizeof key, reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), key_key, sizeof key_key);

	// Decrypt the message.
	unsigned char plaintext_buf[sizeof ciphertext - crypto_secretbox_MACBYTES];
	if (crypto_secretbox_open_easy(plaintext_buf, ciphertext, sizeof ciphertext, nonce, key) != 0) return "Failed to decrypt ciphertext.";

	// Unpad the message.
	string plaintext;
	size_t plaintext_size;
	if (sodium_unpad(&plaintext_size, plaintext_buf, sizeof plaintext_buf, 16) != 0) return "Failed to unpad message.";
	for (unsigned int i = 0; i < plaintext_size; ++i) plaintext.push_back(plaintext_buf[i]);

	outputOSS << "Password: " << (password.length() == 0 ? ":x:" : ":white_check_mark:") << endl;
	outputOSS << "**Result:**" << endl;
	outputOSS << plaintext;

	return outputOSS.str();
}

EMSCRIPTEN_BINDINGS(nxdecrypt) {
	register_vector<string>("VecStr");
	emscripten::function("run", &run);
}
