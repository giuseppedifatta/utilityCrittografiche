// Sample.cpp

#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"

using namespace CryptoPP;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>

int main(int argc, char* argv[])
{
	try
	{
		////////////////////////////////////////////////
		// Generate keys
		AutoSeededRandomPool rng;

		InvertibleRSAFunction parameters;
		parameters.GenerateRandomWithKeySize( rng, 1024 );

		RSA::PrivateKey privateKey( parameters );
		RSA::PublicKey publicKey( parameters );

		SecByteBlock key( AES::MAX_KEYLENGTH ); //AES::MAX_KEYLENGTH=32
		rng.GenerateBlock( key, key.size() );


		std::string plain = std::string(reinterpret_cast<const char*>(key.data()), key.size());


		string cipher, recovered;
		cout << "plain: " << plain << endl;

		////////////////////////////////////////////////
		// Encryption
		RSAES_OAEP_SHA_Encryptor rsaEncryptor( publicKey );

		StringSource( plain, true,
				new PK_EncryptorFilter( rng, rsaEncryptor,
						new StringSink( cipher )
				) // PK_EncryptorFilter
		); // StringSource

		cout << "cipher:" << cipher << endl;

		string encodedCipher;
		StringSource(cipher,true,
				new HexEncoder(
						new StringSink(encodedCipher)
				)//HexEncoder
		);//StringSource
		cout << "encoded cipher: " << encodedCipher << endl;
		////////////////////////////////////////////////
		////////////////////////////////////////////////

		////////////////////////////////////////////////

		string decodedCipher;
		StringSource(encodedCipher,true,
				new HexDecoder(
						new StringSink(decodedCipher)
				)//HexDecoder
		);//StringSource
		cout << "decodedCipher:" << decodedCipher << endl;

		// Decryption
		RSAES_OAEP_SHA_Decryptor rsaDecryptor( privateKey );

		AutoSeededRandomPool rng1;
		StringSource( decodedCipher, true,
				new PK_DecryptorFilter( rng1, rsaDecryptor,
						new StringSink( recovered )
				) // PK_EncryptorFilter
		); // StringSource


		SecByteBlock recoveredKey(reinterpret_cast<const byte*>(recovered.data()), recovered.size());
		std::string recovered2 = std::string(reinterpret_cast<const char*>(key.data()), key.size());

		assert( recovered == recovered2 );

		cout << "recovered: " << recovered << endl;
	}
	catch( CryptoPP::Exception& e )
	{
		cerr << "Caught Exception..." << endl;
		cerr << e.what() << endl;
	}


	return 0;
}

