#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

struct crypto_config
{
	const char * m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};

#endif /* _PROGTEST_ */

#define BLOCK_SIZE 1024
#define HEAD_SIZE 18

bool encryptOrDecrypt(evp_cipher_ctx_st * context, const evp_cipher_st * cryptographer, crypto_config & config, ifstream & in_file, ofstream & out_file, bool inverseProcess)
{
    vector<uint8_t> cTextByBlocks(BLOCK_SIZE);
    vector<uint8_t> pTextByBlocks(BLOCK_SIZE);
    vector<uint8_t> cText;
    int cipherTextBlockLen, cipherTextLen;

    int init = inverseProcess ? EVP_DecryptInit_ex(context, cryptographer, nullptr, config.m_key.get(), config.m_IV.get())
                              : EVP_EncryptInit_ex(context, cryptographer, nullptr, config.m_key.get(), config.m_IV.get());
    if (init <= 0)
    {
        EVP_CIPHER_CTX_free(context);
        return false;
    }

    while (true)
    {
        in_file.read((char *)(pTextByBlocks.data()), BLOCK_SIZE);
        if (in_file.gcount() <= 0)
            break;

        int update = inverseProcess ? EVP_DecryptUpdate(context, cTextByBlocks.data(), &cipherTextBlockLen, pTextByBlocks.data(), (int)in_file.gcount())
                                    : EVP_EncryptUpdate(context, cTextByBlocks.data(), &cipherTextBlockLen, pTextByBlocks.data(), (int)in_file.gcount());
        if (update <= 0)
        {
            EVP_CIPHER_CTX_free(context);
            return false;
        }

        out_file.write(reinterpret_cast<char *>(cTextByBlocks.data()), cipherTextBlockLen);
        if (!out_file)
        {
            EVP_CIPHER_CTX_free(context);
            return false;
        }

        cTextByBlocks.clear();
        pTextByBlocks.clear();
    }

    auto cypherBlockSize = EVP_CIPHER_get_block_size(cryptographer);
    cText.resize(BLOCK_SIZE + cypherBlockSize);
    int final = inverseProcess ? EVP_DecryptFinal_ex(context, cText.data(), &cipherTextLen)
                               : EVP_EncryptFinal_ex(context, cText.data(), &cipherTextLen);
    if (final <= 0)
    {
        EVP_CIPHER_CTX_free(context);
        return false;
    }
    out_file.write(reinterpret_cast<char*>(cText.data()), cipherTextLen);
    if (!out_file)
    {
        EVP_CIPHER_CTX_free(context);
        return false;
    }
    return true;
};

bool checkConfig(crypto_config & config, const evp_cipher_st * cryptographer, evp_cipher_ctx_st * context, bool inverseProcess)
{
    auto keyLength = EVP_CIPHER_get_key_length(cryptographer);
    if (keyLength > (int)config.m_key_len || config.m_key == nullptr) //maybe mistake
    {
        if (!inverseProcess)
        {
            config.m_key_len = keyLength;
            config.m_key = make_unique<uint8_t[]>(keyLength);
            RAND_bytes(config.m_key.get(), keyLength);
        }
        else
        {
            EVP_CIPHER_CTX_free(context);
            return false;
        }
    }

    auto IVLength = EVP_CIPHER_get_iv_length(cryptographer);
    if (IVLength > (int)config.m_IV_len || (IVLength > 0 && config.m_IV == nullptr)) //maybe mistake
    {
        if (!inverseProcess)
        {
            config.m_IV_len = IVLength;
            config.m_IV = make_unique<uint8_t[]>(IVLength);
            RAND_bytes(config.m_IV.get(), IVLength);
        }
        else
        {
            EVP_CIPHER_CTX_free(context);
            return false;
        }
    }

    return true;
};

bool copyHead(ifstream & in_file, ofstream & out_file)
{
    vector<char> head(HEAD_SIZE);
    in_file.read(head.data(), HEAD_SIZE);
    if (in_file.gcount() < HEAD_SIZE || !in_file)
        return false;
    out_file.write(head.data(), HEAD_SIZE);
    if (!out_file)
        return false;
    return true;
};

bool process(const std::string & in_filename, const std::string & out_filename, crypto_config & config, bool inverseProcess)
{
    ifstream in_file(in_filename, ios::binary);
    ofstream out_file(out_filename, ios::binary);

    if (!in_file || !out_file || !in_file.is_open() || !out_file.is_open())
        return false;

    if (!copyHead(in_file, out_file))
        return false;

    auto context = EVP_CIPHER_CTX_new();
    if (context == nullptr)
        return false;

    auto cryptographer = EVP_get_cipherbyname(config.m_crypto_function);
    if (cryptographer == nullptr)
    {
        EVP_CIPHER_CTX_free(context);
        return false;
    }

    if (!checkConfig(config, cryptographer, context, inverseProcess))
        return false;

    if (!encryptOrDecrypt(context, cryptographer, config, in_file, out_file, inverseProcess))
        return false;

    EVP_CIPHER_CTX_free(context);
    in_file.close();
    out_file.close();

    return true;
};

bool encrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
    return process(in_filename, out_filename, config, false);
}

bool decrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
    return process(in_filename, out_filename, config, true);
}


#ifndef __PROGTEST__

bool compare_files(const char *name1, const char *name2)
{
};

int main ( void )
{
	crypto_config config {nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
 	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );

	assert( decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );

	assert( decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );

	assert( decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );

	// CBC mode
	config.m_crypto_function = "AES-128-CBC";
	config.m_IV = std::make_unique<uint8_t[]>(16);
	config.m_IV_len = 16;
	memset(config.m_IV.get(), 0, 16);

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );

	assert( decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );

	assert( decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );

	assert( decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );
	return 0;
}

#endif /* _PROGTEST_ */
