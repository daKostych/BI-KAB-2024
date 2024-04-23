#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

using namespace std;

#endif /* __PROGTEST__ */

#define BLOCK_SIZE 1024

bool seal( string_view inFile, string_view outFile, string_view publicKeyFile, string_view symmetricCipher )
{
    string in(inFile);
    ifstream in_file(in, ios::binary);
    string out(outFile);
    ofstream out_file(out, ios::binary);

    if (!in_file || !out_file || !in_file.is_open() || !out_file.is_open())
    {
        remove(out.c_str());
        return false;
    }

    auto context = EVP_CIPHER_CTX_new();
    if (context == nullptr)
    {
        remove(out.c_str());
        return false;
    }

    string name(symmetricCipher);
    auto cryptographer = EVP_get_cipherbyname(name.c_str());
    if (cryptographer == nullptr)
    {
        EVP_CIPHER_CTX_free(context);
        remove(out.c_str());
        return false;
    }

    string key(publicKeyFile);
    auto pkf = fopen(key.c_str(), "rb");
    if (!pkf)
    {
        EVP_CIPHER_CTX_free(context);
        remove(out.c_str());
        return false;
    }
    auto publicKey = PEM_read_PUBKEY(pkf, nullptr, nullptr, nullptr);
    fclose(pkf);
    if (publicKey == nullptr)
    {
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(publicKey);
        remove(out.c_str());
        return false;
    }

    auto encryptedKeyLen = EVP_PKEY_size(publicKey);
    auto encryptedKey = new uint8_t[encryptedKeyLen];
    auto IVLen = EVP_CIPHER_iv_length(cryptographer);
    auto IV = new uint8_t[IVLen];
    int check = EVP_SealInit(context, cryptographer, &encryptedKey, &encryptedKeyLen, IV, &publicKey, 1);
    if (check <= 0)
    {
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(publicKey);
        delete [] encryptedKey;
        delete [] IV;
        remove(out.c_str());
        return false;
    }

    int NID = EVP_CIPHER_nid(cryptographer);
    if (NID <= 0)
    {
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(publicKey);
        delete [] encryptedKey;
        delete [] IV;
        remove(out.c_str());
        return false;
    }

    out_file.write(reinterpret_cast<char *>(&NID), sizeof(NID));
    if (!out_file)
    {
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(publicKey);
        delete [] encryptedKey;
        delete [] IV;
        remove(out.c_str());
        return false;
    }
    out_file.write(reinterpret_cast<char *>(&encryptedKeyLen), sizeof(encryptedKeyLen));
    if (!out_file)
    {
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(publicKey);
        delete [] encryptedKey;
        delete [] IV;
        remove(out.c_str());
        return false;
    }
    out_file.write(reinterpret_cast<char *>(encryptedKey), encryptedKeyLen);
    if (!out_file)
    {
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(publicKey);
        delete [] encryptedKey;
        delete [] IV;
        remove(out.c_str());
        return false;
    }
    out_file.write(reinterpret_cast<char *>(IV), IVLen);
    if (!out_file)
    {
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(publicKey);
        delete [] encryptedKey;
        delete [] IV;
        remove(out.c_str());
        return false;
    }

    vector<uint8_t> cTextByBlocks(BLOCK_SIZE);
    vector<uint8_t> pTextByBlocks(BLOCK_SIZE);
    vector<uint8_t> cText;
    int cipherTextBlockLen, cipherTextLen;
    while(true)
    {
        in_file.read((char *)(pTextByBlocks.data()), BLOCK_SIZE);
        if (in_file.gcount() <= 0)
            break;
        int update = EVP_SealUpdate(context, cTextByBlocks.data(), &cipherTextBlockLen, pTextByBlocks.data(), (int)in_file.gcount());
        if (update <= 0)
        {
            EVP_CIPHER_CTX_free(context);
            delete [] encryptedKey;
            delete [] IV;
            remove(out.c_str());
            return false;
        }
        out_file.write(reinterpret_cast<char *>(cTextByBlocks.data()), cipherTextBlockLen);
        if (!out_file)
        {
            EVP_CIPHER_CTX_free(context);
            EVP_PKEY_free(publicKey);
            delete [] encryptedKey;
            delete [] IV;
            remove(out.c_str());
            return false;
        }
        cTextByBlocks.clear();
        pTextByBlocks.clear();
    }
    auto cypherBlockSize = EVP_CIPHER_get_block_size(cryptographer);
    cText.resize(BLOCK_SIZE + cypherBlockSize);
    int final = EVP_SealFinal(context, cText.data(), &cipherTextLen);
    if (final <= 0)
    {
        EVP_CIPHER_CTX_free(context);
        delete [] encryptedKey;
        delete [] IV;
        remove(out.c_str());
        return false;
    }
    out_file.write(reinterpret_cast<char*>(cText.data()), cipherTextLen);
    if (!out_file)
    {
        EVP_CIPHER_CTX_free(context);
        delete [] encryptedKey;
        delete [] IV;
        remove(out.c_str());
        return false;
    }

    EVP_CIPHER_CTX_free(context);
    EVP_PKEY_free(publicKey);
    delete [] encryptedKey;
    delete [] IV;
    in_file.close();
    out_file.close();

    return true;
}

bool open( string_view inFile, string_view outFile, string_view privateKeyFile )
{
    string in(inFile);
    ifstream in_file(in, ios::binary);
    string out(outFile);
    ofstream out_file(out, ios::binary);

    if (!in_file || !out_file || !in_file.is_open() || !out_file.is_open())
        return false;

    auto context = EVP_CIPHER_CTX_new();
    if (context == nullptr)
        return false;

    char * nid = new char[4];
    int NID;
    in_file.read(nid, 4);
    if (in_file.gcount() < 4)
    {
        EVP_CIPHER_CTX_free(context);
        delete [] nid;
        remove(out.c_str());
        return false;
    }
    memcpy(&NID, nid, 4);
    if (NID <= 0)
    {
        EVP_CIPHER_CTX_free(context);
        delete [] nid;
        remove(out.c_str());
        return false;
    }

    char * ekl = new char[4];
    int encryptedKeyLen;
    in_file.read(ekl, 4);
    if (in_file.gcount() < 4)
    {
        EVP_CIPHER_CTX_free(context);
        delete [] nid;
        delete [] ekl;
        remove(out.c_str());
        return false;
    }
    memcpy(&encryptedKeyLen, ekl, 4);
    if (encryptedKeyLen <= 0)
    {
        EVP_CIPHER_CTX_free(context);
        delete [] nid;
        delete [] ekl;
        remove(out.c_str());
        return false;
    }

    char * encryptedKey = new char[encryptedKeyLen];
    in_file.read(encryptedKey, encryptedKeyLen);
    if (in_file.gcount() < encryptedKeyLen)
    {
        EVP_CIPHER_CTX_free(context);
        delete [] nid;
        delete [] ekl;
        delete [] encryptedKey;
        remove(out.c_str());
        return false;
    }

    auto cryptographer = EVP_get_cipherbynid(NID);
    if (cryptographer == nullptr)
    {
        EVP_CIPHER_CTX_free(context);
        delete [] nid;
        delete [] ekl;
        delete [] encryptedKey;
        remove(out.c_str());
        return false;
    }

    string key(privateKeyFile);
    auto pkf = fopen(key.c_str(), "rb");
    if (!pkf)
    {
        EVP_CIPHER_CTX_free(context);
        delete [] nid;
        delete [] ekl;
        delete [] encryptedKey;
        remove(out.c_str());
        return false;
    }
    auto privateKey = PEM_read_PrivateKey(pkf, nullptr, nullptr, nullptr);
    fclose(pkf);
    if (privateKey == nullptr)
    {
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(privateKey);
        delete [] nid;
        delete [] ekl;
        delete [] encryptedKey;
        remove(out.c_str());
        return false;
    }

    auto IVLen = EVP_CIPHER_iv_length(cryptographer);
    char * IV = new char[IVLen];
    in_file.read(IV, IVLen);
    if (in_file.gcount() < IVLen)
    {
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(privateKey);
        delete [] nid;
        delete [] ekl;
        delete [] encryptedKey;
        delete [] IV;
        remove(out.c_str());
        return false;
    }

    int check = EVP_OpenInit(context, cryptographer,
                             reinterpret_cast<unsigned char *>(encryptedKey),encryptedKeyLen,
                             reinterpret_cast<unsigned char *>(IV), privateKey);
    if (check <= 0)
    {
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(privateKey);
        delete [] nid;
        delete [] ekl;
        delete [] encryptedKey;
        delete [] IV;
        remove(out.c_str());
        return false;
    }

    vector<uint8_t> cTextByBlocks(BLOCK_SIZE);
    vector<uint8_t> pTextByBlocks(BLOCK_SIZE);
    vector<uint8_t> cText;
    int cipherTextBlockLen, cipherTextLen;
    while(true)
    {
        in_file.read((char *)(pTextByBlocks.data()), BLOCK_SIZE);
        if (in_file.gcount() <= 0)
            break;
        int update = EVP_OpenUpdate(context, cTextByBlocks.data(), &cipherTextBlockLen, pTextByBlocks.data(), (int)in_file.gcount());
        if (update <= 0)
        {
            EVP_CIPHER_CTX_free(context);
            EVP_PKEY_free(privateKey);
            delete [] nid;
            delete [] ekl;
            delete [] encryptedKey;
            delete [] IV;
            remove(out.c_str());
            return false;
        }
        out_file.write(reinterpret_cast<char *>(cTextByBlocks.data()), cipherTextBlockLen);
        if (!out_file)
        {
            EVP_CIPHER_CTX_free(context);
            EVP_PKEY_free(privateKey);
            delete [] nid;
            delete [] ekl;
            delete [] encryptedKey;
            delete [] IV;
            remove(out.c_str());
            return false;
        }
        cTextByBlocks.clear();
        pTextByBlocks.clear();
    }
    auto cypherBlockSize = EVP_CIPHER_get_block_size(cryptographer);
    cText.resize(BLOCK_SIZE + cypherBlockSize);
    int final = EVP_OpenFinal(context, cText.data(), &cipherTextLen);
    if (final <= 0)
    {
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(privateKey);
        delete [] nid;
        delete [] ekl;
        delete [] encryptedKey;
        delete [] IV;
        remove(out.c_str());
        return false;
    }
    out_file.write(reinterpret_cast<char*>(cText.data()), cipherTextLen);
    if (!out_file)
    {
        EVP_CIPHER_CTX_free(context);
        delete [] nid;
        delete [] ekl;
        delete [] encryptedKey;
        delete [] IV;
        remove(out.c_str());
        return false;
    }

    EVP_CIPHER_CTX_free(context);
    EVP_PKEY_free(privateKey);
    delete [] nid;
    delete [] ekl;
    delete [] encryptedKey;
    delete [] IV;
    in_file.close();
    out_file.close();

    return true;
}



#ifndef __PROGTEST__

int main ( void )
{
    assert( seal("fileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-cbc") );
    assert( open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem") );

    assert( open("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem") );

    return 0;
}

#endif /* __PROGTEST__ */

