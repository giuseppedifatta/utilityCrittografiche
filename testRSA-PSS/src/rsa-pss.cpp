/*
 * rsa-pss.cpp
 *
 *  Created on: 15/set/2017
 *      Author: giuseppe
 */
#include <string>
#include <iostream>

#include "cryptopp/osrng.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hmac.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/secblock.h"
#include "cryptopp/rsa.h"
#include "cryptopp/base64.h"
#include "cryptopp/files.h"
#include "cryptopp/pssr.h"
#include <cryptopp/pwdbased.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

#include "RSA-PSS_utils.h"

using namespace std;
using namespace CryptoPP;
void getPublicKeyFromCert(CryptoPP::BufferedTransformation & certin,
		CryptoPP::BufferedTransformation & keyout) {
	/**
	 * Reads an X.509 v3 certificate from certin, extracts the subjectPublicKeyInfo structure
	 * (which is one way PK_Verifiers can get their key material) and writes it to keyout
	 *
	 * @throws CryptoPP::BERDecodeError
	 */
	BERSequenceDecoder x509Cert(certin);
	BERSequenceDecoder tbsCert(x509Cert);

	// ASN.1 from RFC 3280
	// TBSCertificate  ::=  SEQUENCE  {
	// version         [0]  EXPLICIT Version DEFAULT v1,

	// consume the context tag on the version
	BERGeneralDecoder context(tbsCert, 0xa0);
	word32 ver;

	// only want a v3 cert
	BERDecodeUnsigned<word32>(context, ver, INTEGER, 2, 2);

	// serialNumber         CertificateSerialNumber,
	Integer serial;
	serial.BERDecode(tbsCert);

	// signature            AlgorithmIdentifier,
	BERSequenceDecoder signature(tbsCert);
	signature.SkipAll();

	// issuer               Name,
	BERSequenceDecoder issuerName(tbsCert);
	issuerName.SkipAll();

	// validity             Validity,
	BERSequenceDecoder validity(tbsCert);
	validity.SkipAll();

	// subject              Name,
	BERSequenceDecoder subjectName(tbsCert);
	subjectName.SkipAll();

	// subjectPublicKeyInfo SubjectPublicKeyInfo,
	BERSequenceDecoder spki(tbsCert);
	DERSequenceEncoder spkiEncoder(keyout);

	spki.CopyTo(spkiEncoder);
	spkiEncoder.MessageEnd();

	spki.SkipAll();
	tbsCert.SkipAll();
	x509Cert.SkipAll();
}

RSA::PrivateKey extractPrivatePemKey(const char * key_pem) {
	/*	string RSA_PRIV_KEY = "-----BEGIN RSA PRIVATE KEY-----\n"
	 "MIIBOgIBAAJBAK8Q+ToR4tWGshaKYRHKJ3ZmMUF6jjwCS/u1A8v1tFbQiVpBlxYB\n"
	 "paNcT2ENEXBGdmWqr8VwSl0NBIKyq4p0rhsCAQMCQHS1+3wL7I5ZzA8G62Exb6RE\n"
	 "INZRtCgBh/0jV91OeDnfQUc07SE6vs31J8m7qw/rxeB3E9h6oGi9IVRebVO+9zsC\n"
	 "IQDWb//KAzrSOo0P0yktnY57UF9Q3Y26rulWI6LqpsxZDwIhAND/cmlg7rUz34Pf\n"
	 "SmM61lJEmMEjKp8RB/xgghzmCeI1AiEAjvVVMVd8jCcItTdwyRO0UjWU4JOz0cnw\n"
	 "5BfB8cSIO18CIQCLVPbw60nOIpUClNxCJzmMLbsrbMcUtgVS6wFomVvsIwIhAK+A\n"
	 "YqT6WwsMW2On5l9di+RPzhDT1QdGyTI5eFNS+GxY\n"
	 "-----END RSA PRIVATE KEY-----";
	 */
	static string HEADER = "-----BEGIN RSA PRIVATE KEY-----";
	static string FOOTER = "-----END RSA PRIVATE KEY-----";
	//

	std::ifstream ifs(key_pem);
	std::string content((std::istreambuf_iterator<char>(ifs)),
			(std::istreambuf_iterator<char>()));

	//cout << content << endl;
	size_t pos1, pos2;
	pos1 = content.find(HEADER);
	if (pos1 == string::npos)
		throw runtime_error("PEM header not found");

	pos2 = content.find(FOOTER, pos1 + 1);
	if (pos2 == string::npos)
		throw runtime_error("PEM footer not found");

	// Start position and length
	pos1 = pos1 + HEADER.length();
	pos2 = pos2 - pos1;
	string keystr = content.substr(pos1, pos2);

	// Base64 decode, place in a ByteQueue
	ByteQueue queue;
	Base64Decoder decoder;

	decoder.Attach(new Redirector(queue));
	decoder.Put((const byte*) keystr.data(), keystr.length());
	decoder.MessageEnd();

	// Write to file for inspection
	FileSink fs("decoded-key.der");
	queue.CopyTo(fs);
	fs.MessageEnd();

	CryptoPP::RSA::PrivateKey rsaPrivate;
	try {

		rsaPrivate.BERDecodePrivateKey(queue, false /*paramsPresent*/,
				queue.MaxRetrievable());

		// BERDecodePrivateKey is a void function. Here's the only check
		// we have regarding the DER bytes consumed.
		if (!queue.IsEmpty()) {
			cerr << "errore: DER bytes not proper consumed" << endl;
			exit(1);
		}

		AutoSeededRandomPool prng;
		bool valid = rsaPrivate.Validate(prng, 3);
		if (!valid){
			cerr << "RSA private key is not valid" << endl;
		}
		cout << "RSA private key is valid" << endl;
		cout << "N:" << rsaPrivate.GetModulus() << endl;
		cout << "E:" << rsaPrivate.GetPublicExponent() << endl;
		cout << "D:" << rsaPrivate.GetPrivateExponent() << endl;

	} catch (const Exception& ex) {
		cerr << ex.what() << endl;
		exit(1);
	}
	return rsaPrivate;
}

int main(){
	string data = "ciao";
	const char * filePrivateKey = "/home/giuseppe/myCA/intermediate/private/localhost.key.pem";
	CryptoPP::RSA::PrivateKey privateKey = extractPrivatePemKey(filePrivateKey);
	ByteQueue queue;
	privateKey.Save(queue);
	HexEncoder encoder;
	queue.CopyTo(encoder);
	encoder.MessageEnd();

	string s;
	StringSink ss(s);
	encoder.CopyTo(ss);
	ss.MessageEnd();
	cout << "PrivateKey:" << s << endl;

	cout << "Data to sign: " << data << endl;

	string signature;
	string encodedSignature;
	////////////////////////////////////////////////
	try{
		// Sign and Encode
		RSASS<PSS, SHA512>::Signer signer(privateKey);

		AutoSeededRandomPool rng;

		StringSource(data, true,
				new SignerFilter(rng, signer, new StringSink(signature)) // SignerFilter
		);// StringSource
		cout << " Signature: " << signature << endl;

		StringSource(signature,true,
				new HexEncoder(
						new StringSink(encodedSignature)
				)//HexEncoder
		);//StringSource
		cout << "Signature encoded: " << encodedSignature << endl;

		//------ verifica signature
		FileSource certin(
				"/home/giuseppe/myCA/intermediate/certs/localhost.cert.der", true,
				NULL, true);
		FileSink keyout("localhost-public.key", true);

		getPublicKeyFromCert(certin, keyout);

		//non dimenticare di chiudere il buffer!!!!!!!
		keyout.MessageEnd();

		RSA::PublicKey publicKey;
		LoadPublicKey("localhost-public.key", publicKey);


		ByteQueue queue;
		publicKey.Save(queue);
		HexEncoder encoder;
		queue.CopyTo(encoder);
		encoder.MessageEnd();

		string s;
		StringSink ss(s);
		encoder.CopyTo(ss);
		ss.MessageEnd();
		cout << "PublicKey encoded: " << s << endl;


		////////////////////////////////////////////////
		// Verify and Recover
		RSASS<PSS, SHA512>::Verifier verifier(publicKey);
		cout << "Data to verify:" << data + signature << endl;
		StringSource(data + signature, true,
				new SignatureVerificationFilter(verifier, NULL,
						SignatureVerificationFilter::THROW_EXCEPTION) // SignatureVerificationFilter
		);// StringSource

		cout << "Verified signature on message" << endl;

	} // try

	catch (CryptoPP::Exception& e) {
		cerr << "Error: " << e.what() << endl;
	}

	return 0;
}
