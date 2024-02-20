#include <emscripten/bind.h>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <random>

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
	if (args.size() <= 1)
		return "## Usage: `-t nxencrypt [<password>/--nopassword] <message>`\nAdvanced text encryption program running directly on Assyst's sandbox environment via WebAssembly.\n\nExample:\n- `-t nxencrypt 123456 My secret message`\n- `-t nxencrypt --nopassword Hello World`\n\nNote:\nUse `-t nxdecrypt` to decrypt a message.";

	ostringstream outputOSS;

	string plaintext;
	string password(args.at(0));
	unsigned char key_key[crypto_generichash_KEYBYTES] = { 0xed, 0x15, 0x73, 0x95, 0xa4, 0xd1, 0x05, 0xbc, 0xca, 0x36, 0x1f, 0x4e, 0xde, 0x64, 0x78, 0x5c, 0x88, 0xb4, 0x27, 0x44, 0xcb, 0x67, 0xe3, 0x19, 0xf9, 0x58, 0x2f, 0xbe, 0xbc, 0xea, 0x0f, 0xc9 }; // blake2b-256("Noxturnix")
	unsigned char key[crypto_secretbox_KEYBYTES];
	unsigned char nonce[crypto_secretbox_NONCEBYTES];

	if (LowerString(password) == "--nopassword")
		password.clear();
	for (unsigned int i = 1; i < args.size(); ++i) {
		plaintext += args.at(i);
		if (args.size() - 1 != i) plaintext.push_back(' ');
	}

	// Hash the password.
	crypto_generichash(key, sizeof key, reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), key_key, sizeof key_key);

	// Generate random nonce.
	unsigned random_seed = std::chrono::system_clock::now().time_since_epoch().count();
	default_random_engine generator(random_seed);
	uniform_int_distribution<int> distribution(0, 255);
	for (unsigned int i = 0; i < sizeof nonce; ++i)
		nonce[i] = distribution(generator);

	// Pad the message.
	unsigned char plaintext_buf[plaintext.length() + 16];
	size_t plaintext_buf_padded_size;
	for (unsigned int i = 0; i < plaintext.length(); ++i) plaintext_buf[i] = plaintext.at(i);
	if (sodium_pad(&plaintext_buf_padded_size, plaintext_buf, plaintext.length(), 16, sizeof plaintext_buf) != 0) return "Padding failed.";

	// Encrypt the message.
	unsigned char ciphertext[crypto_secretbox_MACBYTES + plaintext_buf_padded_size];
	crypto_secretbox_easy(ciphertext, plaintext_buf, plaintext_buf_padded_size, nonce, key);

	// Concatenate nonce.
	unsigned char encrypted[sizeof ciphertext + crypto_secretbox_NONCEBYTES];
	for (unsigned int i = 0; i < sizeof ciphertext; ++i) encrypted[i] = ciphertext[i];
	for (unsigned int i = sizeof ciphertext; i < sizeof encrypted; ++i) encrypted[i] = nonce[i - sizeof ciphertext];

	// Base64 encode.
	char encrypted_base64[sodium_base64_ENCODED_LEN(sizeof encrypted, sodium_base64_VARIANT_ORIGINAL)];
	sodium_bin2base64(encrypted_base64, sizeof encrypted_base64, encrypted, sizeof encrypted, sodium_base64_VARIANT_ORIGINAL);

	outputOSS << "Password: " << (password.length() == 0 ? ":x:" : ":white_check_mark:") << endl;
	outputOSS << "**Result:**" << endl;
	outputOSS << "```" << encrypted_base64 << "```";

	return outputOSS.str();
}

EMSCRIPTEN_BINDINGS(nxencrypt) {
	register_vector<string>("VecStr");
	emscripten::function("run", &run);
}
