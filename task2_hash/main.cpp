#ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

#endif /* __PROGTEST__ */

string toHex(const unsigned char * str, size_t size)
{
    string res;
    stringstream stream;
    for(size_t i = 0; i < size; i++)
        stream << hex << setw(2) << setfill('0') << (int)str[i];
    res = stream.str();
    return res;
}

int findHash (int numberZeroBits, string & outputMessage, string & outputHash)
{
    if (numberZeroBits < 0 || numberZeroBits > EVP_MAX_MD_SIZE)
        return 0;

    bool stop = false;
    string hashFunction = "sha512";  // zvolena hashovaci funkce ("sha1", "md5", ...)
    auto * text = new unsigned char[EVP_MAX_MD_SIZE];

    EVP_MD_CTX * ctx;  // struktura kontextu
    const EVP_MD * type; // typ pouzite hashovaci funkce
    auto * hash = new unsigned char[EVP_MAX_MD_SIZE]; // char pole pro hash - 64 bytu (max pro sha 512)
    unsigned int length;  // vysledna delka hashe

    /* Inicializace OpenSSL hash funkci */
    OpenSSL_add_all_digests();
    /* Zjisteni, jaka hashovaci funkce ma byt pouzita */
    type = EVP_get_digestbyname(hashFunction.c_str());

    /* Pokud predchozi prirazeni vratilo -1, tak nebyla zadana spravne hashovaci funkce */
    if (!type)
    {
        delete[] text;
        delete[] hash;
        return 0;
    }

    ctx = EVP_MD_CTX_new(); // create context for hashing
    if (ctx == nullptr)
    {
        delete[] text;
        delete[] hash;
        return 0;
    }

    int iteration = 0;
    while(!stop)
    {
        if (!iteration)
            RAND_bytes(text, EVP_MAX_MD_SIZE);
        else
            swap(text, hash);

        /* Hash the text */
        if (!EVP_DigestInit_ex(ctx, type, nullptr)) // context setup for our hash type
        {
            delete[] text;
            delete[] hash;
            return 0;
        }

        if (!EVP_DigestUpdate(ctx, text, EVP_MAX_MD_SIZE)) // feed the message in
        {
            delete[] text;
            delete[] hash;
            return 0;
        }

        if (!EVP_DigestFinal_ex(ctx, hash, &length)) // get the hash
        {
            delete[] text;
            delete[] hash;
            return 0;
        }

        int zeroNum = 0, bitsChecked = 0;
        for (int i = 0; i < EVP_MAX_MD_SIZE; i++)
        {
            if (bitsChecked == numberZeroBits) break;
            for (int j = 0; j < 8; j++, bitsChecked++)
            {
                if (bitsChecked == numberZeroBits) break;
                if (!((hash[i] << j) & 10000000)) zeroNum++;
            }
        }

        zeroNum == numberZeroBits ? stop = true
                                  : stop = false;
        iteration++;
    }

    EVP_MD_CTX_free(ctx); // destroy the context

    outputMessage = toHex(text, EVP_MAX_MD_SIZE);
    outputHash = toHex(hash, EVP_MAX_MD_SIZE);

    delete[] text;
    delete[] hash;
    return 1;
}

int findHashEx (int numberZeroBits, string & outputMessage, string & outputHash, string_view hashType)
{
    bool stop = false;
    string hashFunction(hashType);  // zvolena hashovaci funkce ("sha1", "md5", ...)

    EVP_MD_CTX * ctx;  // struktura kontextu
    const EVP_MD * type; // typ pouzite hashovaci funkce
    unsigned int length;  // vysledna delka hashe

    /* Inicializace OpenSSL hash funkci */
    OpenSSL_add_all_digests();
    /* Zjisteni, jaka hashovaci funkce ma byt pouzita */
    type = EVP_get_digestbyname(hashFunction.c_str());

    if (!type)
        return 0;

    int hashSize = EVP_MD_get_size(type);
    auto * text = new unsigned char[hashSize];
    auto * hash = new unsigned char[hashSize];

    if (numberZeroBits < 0 || numberZeroBits > hashSize)
    {
        delete[] text;
        delete[] hash;
        return 0;
    }

    ctx = EVP_MD_CTX_new(); // create context for hashing
    if (ctx == nullptr)
    {
        delete[] text;
        delete[] hash;
        return 0;
    }

    int iteration = 0;
    while(!stop)
    {
        if (!iteration)
            RAND_bytes(text, hashSize);
        else
            swap(text, hash);

        /* Hash the text */
        if (!EVP_DigestInit_ex(ctx, type, nullptr)) // context setup for our hash type
        {
            delete[] text;
            delete[] hash;
            return 0;
        }

        if (!EVP_DigestUpdate(ctx, text, hashSize)) // feed the message in
        {
            delete[] text;
            delete[] hash;
            return 0;
        }

        if (!EVP_DigestFinal_ex(ctx, hash, &length)) // get the hash
        {
            delete[] text;
            delete[] hash;
            return 0;
        }

        int zeroNum = 0, bitsChecked = 0;
        for (int i = 0; i < hashSize; i++)
        {
            if (bitsChecked == numberZeroBits) break;
            for (int j = 0; j < 8; j++, bitsChecked++)
            {
                if (bitsChecked == numberZeroBits) break;
                if (!((hash[i] << j) & 10000000)) zeroNum++;
            }
        }

        zeroNum == numberZeroBits ? stop = true
                                  : stop = false;
        iteration++;
    }

    EVP_MD_CTX_free(ctx); // destroy the context

    outputMessage = toHex(text, hashSize);
    outputHash = toHex(hash, hashSize);

    delete[] text;
    delete[] hash;
    return 1;
}

#ifndef __PROGTEST__

int checkHash(int bits, const string & hash)
{
    for (int i = 0; i < bits / 4; i++)
        if (hash[i] != '0')
            return 0;
    if ((bits % 4 == 1) && (hash[bits / 4]) > '7')
        return 0;
    if ((bits % 4 == 2) && (hash[bits / 4]) > '3')
        return 0;
    if ((bits % 4 == 3) && (hash[bits / 4]) > '1')
        return 0;

    return 1;
}

int main (void) {
    string hash, message;
    assert(findHash(0, message, hash) == 1);
    assert(!message.empty() && !hash.empty() && checkHash(0, hash));
    message.clear();
    hash.clear();
    assert(findHash(1, message, hash) == 1);
    assert(!message.empty() && !hash.empty() && checkHash(1, hash));
    message.clear();
    hash.clear();
    assert(findHash(2, message, hash) == 1);
    assert(!message.empty() && !hash.empty() && checkHash(2, hash));
    message.clear();
    hash.clear();
    assert(findHash(3, message, hash) == 1);
    assert(!message.empty() && !hash.empty() && checkHash(3, hash));
    message.clear();
    hash.clear();
    assert(findHash(-1, message, hash) == 0);
    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */

