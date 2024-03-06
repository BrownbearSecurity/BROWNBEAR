#ifndef _GLIBCXX_NO_ASSERT
#include <cassert>
#endif
#include <cctype>
#include <cerrno>
#include <cfloat>
#include <ciso646>
#include <climits>
#include <clocale>
#include <cmath>
#include <csetjmp>
#include <csignal>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#if __cplusplus >= 201103L
#include <ccomplex>
#include <cfenv>
#include <cinttypes>
#include <cstdalign>
#include <cstdbool>
#include <cstdint>
#include <ctgmath>
#include <cwchar>
#include <cwctype>
#endif

// C++
#include <algorithm>
#include <bitset>
#include <complex>
#include <deque>
#include <exception>
#include <fstream>
#include <functional>
#include <iomanip>
#include <ios>
#include <iosfwd>
#include <iostream>
#include <istream>
#include <iterator>
#include <limits>
#include <list>
#include <locale>
#include <map>
#include <memory>
#include <new>
#include <numeric>
#include <ostream>
#include <queue>
#include <set>
#include <sstream>
#include <stack>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <typeinfo>
#include <utility>
#include <valarray>
#include <vector>

#if __cplusplus >= 201103L
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <forward_list>
#include <future>
#include <initializer_list>
#include <mutex>
#include <random>
#include <ratio>
#include <regex>
#include <scoped_allocator>
#include <system_error>
#include <thread>
#include <tuple>
#include <typeindex>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#endif

#ifdef _WIN32  // if the current operating system is Windows
#include <windows.h>  // WriteConsoleW
#endif

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iomanip>
#include <cstdio>

using namespace std;

//fonctions
string lowerCaseString(string& source);
string special_shuffle(std::string s);
string encryptAES(const std::string& plaintext, const std::string& key, const std::string& iv);
string decryptAES(const std::string& ciphertext, const std::string& key, const std::string& iv);
string generateAESKey();
string generateIV();
string base64Encode(const std::string& input);
string base64Decode(const std::string& input);
bool substitution(string& source, string cipherKey, string& destination);
bool Encrypted(string& destination, string cipherKeyA, string& encrypted);
bool Encrypted2(string& destination, string cipherKeyB, string& encrypted2);
bool desubstitution(string& source, string cipherKey, string& original);
bool Decrypted(string& sourceB, string cipherKeyA, string& decrypted);
bool Decrypted2(string& sourceB2, string cipherKeyb, string& sourceB);
const int MAX = 26;

//ʕ´• ᴥ•̥`ʔ UTF8
void wprint(std::wstring message)
{
#ifdef _WIN32
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD n_written;
	WriteConsoleW(handle, message.c_str(), (DWORD)message.size(), &n_written, NULL);
#else
	std::wcout << message;
#endif
}

//BROWNBEAR MAIN
int main()
{
	string source;
	string cipherKey;
	string cipherKeyA;
	string cipherKeyB;
	string destination;
	string original;
	string encrypted;
	string encrypted2;
	string sourceB;
	string sourceB2;
	string decrypted;
	string password;
	string alphabet = "/abcdefghijklmnopqrstuvwxyz0123456789-+.,*";
	std::string key, iv, text;
	ifstream inFile;
	system("color 6F");
	system("TITLE BROWNBEAR");

	int choice;
	bool gameOn = true;
	while (gameOn != false) {
		cout << "============================================================================================\n";
		cout << "                                     B R O W N B E A R\n";
		cout << "                                    -------------------";
		cout << " \n";
		wprint(L"                                          ʕ'• ᴥ•̥`ʔ\n");
		wprint(L"                                   \n");
		cout << "============================================================================================\n";
		cout << "   \n";
		cout << " [1] ENCRYPT\n";
		cout << " [2] DECRYPT\n";
		cout << " [3] Keys\n";
		cout << " [4] GENERATE A NEW KEY\n";
		cout << " [5] Exit\n";
		cout << "   \n";
		cout << "============================================================================================\n";
		cout << "                        Enter your choice and press enter: \n";
		cout << "============================================================================================\n";
		cout << "   \n";

		cin >> choice;

		string base64Encoded;
		string encryptedAES;
		string decryptedAES;

		switch (choice)
		{
		case 1:
			try {
			system("cls");
			cout << "Please enter a string: " << endl;
			cin >> source;
			lowerCaseString(source);
			substitution(source, cipherKey, destination);
			Encrypted(destination, cipherKeyA, encrypted);
			Encrypted2(encrypted, cipherKeyB, encrypted2);

			// Encrypt the encrypted2 string using AES
			encryptedAES = encryptAES(encrypted2, key, iv);

			// Base64 encode the encrypted data for safe transmission
			base64Encoded = base64Encode(encryptedAES);

			// Debug output
			cout << "Encrypted text: " << base64Encoded << endl;
			}
			catch (const std::exception& e) {
				cerr << "Error occurred during encryption: " << e.what() << endl;
			}

			break;

		case 2:
			try {
			system("cls");
			cout << "Please enter a string: " << endl;
			cin >> sourceB2;

			// Decode the base64-encoded ciphertext
			sourceB2 = base64Decode(sourceB2);

			// Decrypt the ciphertext using AES
			decryptedAES = decryptAES(sourceB2, key, iv);

			// Perform necessary transformations (if any) to get the original plaintext
			// For example, you might need to desubstitution here
			sourceB2 = decryptedAES;
			lowerCaseString(sourceB2);
			Decrypted2(sourceB2, cipherKeyB, sourceB);
			Decrypted(sourceB, cipherKeyA, decrypted);
			desubstitution(decrypted, cipherKey, original);

			// Debug output
			cout << "Original text: " << original << endl;
			}
			catch (const std::exception& e) {
				cerr << "Error occurred during decryption: " << e.what() << endl;
			}

			break;

		case 3:
			try {
			system("cls");
			cout << "Please enter the key1: " << endl;
			cin >> cipherKey;
			cout << "Please enter the key2: " << endl;
			cin >> cipherKeyA;
			cout << "Please enter the key3: " << endl;
			cin >> cipherKeyB;
			cout << "Enter AES key (16, 24, or 32 bytes): ";
			cin >> key;
			cout << "Enter Initialization Vector (IV) (16 bytes): ";
			cin >> iv;
			}
			catch (const std::exception& e) {
				cerr << "Error occurred during key management: " << e.what() << endl;
			}
			break;
		case 4:
			try {
			system("cls");
			std::cout << special_shuffle(alphabet) << "\n";
			std::cout << special_shuffle(alphabet) << "\n";
			std::cout << special_shuffle(alphabet) << "\n";
			key = generateAESKey();
			iv = generateIV();
			std::cout << "Generated AES key: " << key << std::endl;
			std::cout << "Generated IV: " << iv << std::endl;
			}
			catch (const std::exception& e) {
				cerr << "Error occurred during key generation: " << e.what() << endl;
			}
			break;
		case 5:
			system("cls");
			cout << "End of Program.\n";
			gameOn = false;
			break;
		default:
			system("cls");
			cout << "I'm not sure to understand... \n";
			cout << "Are you sure you know how to write? maybe you should go back to school ;-)\n";
			cout << "What do you want to do?.\n";
			cout << "   \n";
			cin >> choice;
			break;
		}

	}
	return 0;
}

//converts all letters that are upper case to lower case in source
string lowerCaseString(string& source)
{
	unsigned i;
	for (i = 0; i < source.size(); ++i)
	{
		if (isupper(source.at(i)))
		{
			source.at(i) = tolower(source.at(i));
		}
	}
	return source;
}

//encrypts the source string based on the cipher key, then writes the encrypted string to string destination
bool substitution(string& source, string cipherKey, string& destination)
{

	string alphabet = "/abcdefghijklmnopqrstuvwxyz0123456789-+.,*";

	destination = source; // To make sure the size of destination is the same as source

	if (source.size() == 0)
		return false;
	else
	{
		for (unsigned int i = 0; i < source.size(); ++i)
			destination.at(i) = cipherKey.at(alphabet.find(source.at(i)));
		return false;
	}
}

bool Encrypted(string& destination, string cipherKeyA, string& encrypted)
{

	string alphabet = "/abcdefghijklmnopqrstuvwxyz0123456789-+.,*";

	encrypted = destination; // To make sure the size of destination is the same as source

	if (destination.size() == 0)
		return false;
	else
	{
		for (unsigned int i = 0; i < destination.size(); ++i)
			encrypted.at(i) = cipherKeyA.at(alphabet.find(destination.at(i)));
		return false;
	}
}

bool Encrypted2(string& destination, string cipherKeyB, string& encrypted2)
{

	string alphabet = "/abcdefghijklmnopqrstuvwxyz0123456789-+.,*";

	encrypted2 = destination; // To make sure the size of destination is the same as source

	if (destination.size() == 0)
		return false;
	else
	{
		for (unsigned int i = 0; i < destination.size(); ++i)
			encrypted2.at(i) = cipherKeyB.at(alphabet.find(destination.at(i)));
		return false;
	}
}

//encrypts the source string based on the cipher key, then writes the encrypted string to string destination
bool desubstitution(string& decrypted, string cipherKey, string& original)
{

	string alphabet = "/abcdefghijklmnopqrstuvwxyz0123456789-+.,*";

	original = decrypted; // To make sure the size of original is the same as source

	if (decrypted.size() == 0)
		return false;
	else
	{
		for (unsigned int i = 0; i < decrypted.size(); ++i)
			original.at(i) = alphabet.at(cipherKey.find(decrypted.at(i)));
		return false;
	}
}

//encrypts the source string based on the cipher key, then writes the encrypted string to string destination
bool Decrypted(string& sourceB, string cipherKeyA, string& decrypted)
{

	string alphabet = "/abcdefghijklmnopqrstuvwxyz0123456789-+.,*";

	decrypted = sourceB; // To make sure the size of original is the same as source

	if (sourceB.size() == 0)
		return false;
	else
	{
		for (unsigned int i = 0; i < sourceB.size(); ++i)
			decrypted.at(i) = alphabet.at(cipherKeyA.find(sourceB.at(i)));
		return false;
	}
}

bool Decrypted2(string& sourceB2, string cipherKeyB, string& sourceB)
{

	string alphabet = "/abcdefghijklmnopqrstuvwxyz0123456789-+.,*";

	sourceB = sourceB2; // To make sure the size of original is the same as source

	if (sourceB.size() == 0)
		return false;
	else
	{
		for (unsigned int i = 0; i < sourceB2.size(); ++i)
			sourceB.at(i) = alphabet.at(cipherKeyB.find(sourceB2.at(i)));
		return false;
	}
}

std::string special_shuffle(std::string s)
{
	if (s.size() < 3) return s;
	auto begin = std::find_if(s.begin(), s.end(), ::isprint);
	auto end = std::find_if(s.rbegin(), s.rend(), ::isprint).base();
	std::random_shuffle(++begin, --end);
	return s;
}


// Padding function for AES encryption
std::string addPadding(const std::string& input) {
	int paddingSize = AES_BLOCK_SIZE - (input.length() % AES_BLOCK_SIZE);
	char paddingChar = paddingSize;
	return input + std::string(paddingSize, paddingChar);
}

// AES encryption function
std::string encryptAES(const std::string& plaintext, const std::string& key, const std::string& iv) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), (const unsigned char*)iv.c_str());

	int len;
	int ciphertext_len;
	std::string ciphertext(plaintext.size() + AES_BLOCK_SIZE, '\0');
	EVP_EncryptUpdate(ctx, (unsigned char*)&ciphertext[0], &len, (const unsigned char*)plaintext.c_str(), plaintext.size());
	ciphertext_len = len;
	EVP_EncryptFinal_ex(ctx, (unsigned char*)&ciphertext[ciphertext_len], &len);
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext;
}

// AES decryption function
std::string decryptAES(const std::string& ciphertext, const std::string& key, const std::string& iv) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), (const unsigned char*)iv.c_str());

	int len;
	int plaintext_len;
	std::string plaintext(ciphertext.size() + AES_BLOCK_SIZE, '\0');

	// Debug output
	std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;

	EVP_DecryptUpdate(ctx, (unsigned char*)&plaintext[0], &len, (const unsigned char*)ciphertext.c_str(), ciphertext.size());
	plaintext_len = len;

	// Debug output
	std::cout << "Plaintext length after update: " << plaintext_len << std::endl;

	EVP_DecryptFinal_ex(ctx, (unsigned char*)&plaintext[plaintext_len], &len);
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	// Remove padding
	plaintext.resize(plaintext_len);

	// Debug output
	std::cout << "Plaintext: " << plaintext << std::endl;

	return plaintext;
}

// Base64 encode
std::string base64Encode(const std::string& input) {
	BIO* bio, * b64;
	BUF_MEM* bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, input.c_str(), input.length());
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);

	std::string output(bufferPtr->data, bufferPtr->length);

	BIO_free_all(bio);

	return output;
}

std::string base64Decode(const std::string& input) {
	// Create a BIO object for Base64 decoding
	BIO* b64 = BIO_new(BIO_f_base64());
	if (!b64) {
		return ""; // Error handling: unable to create BIO object
	}

	// Ignore newline characters during decoding
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	// Create a memory BIO for reading from input
	BIO* bio = BIO_new_mem_buf(input.data(), input.size());
	if (!bio) {
		BIO_free_all(b64);
		return ""; // Error handling: unable to create memory BIO
	}

	// Push the Base64 BIO onto the memory BIO stack
	BIO_push(b64, bio);

	// Allocate memory for decoded data
	std::unique_ptr<char[]> decodedBuffer(new char[input.size() * 3 / 4 + 1]); // Maximum possible length

	// Read and decode the input data
	int decodedLength = BIO_read(b64, decodedBuffer.get(), input.size() * 3 / 4);
	if (decodedLength <= 0) {
		BIO_free_all(b64);
		return ""; // Error handling: failed to decode or empty input
	}

	// Ensure null termination
	decodedBuffer[decodedLength] = '\0';

	// Clean up resources
	BIO_free_all(b64);

	// Convert decoded data to string
	return std::string(decodedBuffer.get());
}




// Generate random AES key
std::string generateAESKey() {
	unsigned char key[AES_BLOCK_SIZE * 2] = { 0 };
	RAND_bytes(key, AES_BLOCK_SIZE);
	char hex_key[AES_BLOCK_SIZE * 2 + 1] = { 0 };
	for (int i = 0; i < AES_BLOCK_SIZE; ++i)
		sprintf_s(hex_key + 2 * i, sizeof(hex_key) - 2 * i, "%02X", key[i]);
	return std::string(hex_key);
}

// Generate random IV
std::string generateIV() {
	unsigned char iv[AES_BLOCK_SIZE] = { 0 };
	RAND_bytes(iv, AES_BLOCK_SIZE);
	char hex_iv[AES_BLOCK_SIZE * 2 + 1] = { 0 };
	for (int i = 0; i < AES_BLOCK_SIZE; ++i)
		sprintf_s(hex_iv + 2 * i, sizeof(hex_iv) - 2 * i, "%02X", iv[i]);
	return std::string(hex_iv);
}