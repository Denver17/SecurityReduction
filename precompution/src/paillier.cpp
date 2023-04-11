/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */

#include<iostream>
#include "paillier.h"
#include "tools.h"
#include<ctime>

using namespace std;

Paillier::SecretKey::SecretKey(const NTL::ZZ& p, const NTL::ZZ& q){
	this->N = p*q;
	this->phi_N = (p-1)*(q-1);
	this->phi_N_inv = NTL::InvMod(this->phi_N, this->N);
	// this->N_square = this->N * this->N;
}

NTL::ZZ Paillier::SecretKey::get_phi_N(){
	return this->phi_N;
}

NTL::ZZ Paillier::SecretKey::get_phi_N_inv(){
	return this->phi_N_inv;
}

NTL::ZZ Paillier::SecretKey::get_N(){
	return this->N;
}

// NTL::ZZ Paillier::SecretKey::get_N_square(){
// 	return this->N_square;
// }

Paillier::PublicKey::PublicKey(){
	// ......
}

Paillier::PublicKey::PublicKey(const NTL::ZZ& N, long Nlens){
	this->Nlens = Nlens;
	this->N = N;
	// this->G = N + 1;
	// this->N_square = N * N;

	NTL::ZZ x; //  1 < x < N
	while(true){
		x = NTL::RandomBnd(N);
		if (NTL::GCD(x, N) == 1 && x > 1)
			break;
	}

	NTL::ZZ H = NTL::MulMod(x, x, this->N);
	H = NTL::MulMod(-1, H, this->N);
	this->Hs = NTL::PowerMod(H, this->N, this->N * this->N);

	NTL::ZZ num = this->Hs;
	for(long i = 0; i < (Nlens + 1) / 2; i++) {
		this->vec.push_back(num);
		num = NTL::MulMod(num, num, this->N * this->N);
	}
}

NTL::ZZ Paillier::PublicKey::get_N(){
	return this->N;
}

// NTL::ZZ Paillier::PublicKey::get_G(){
// 	return this->G;
// }

long Paillier::PublicKey::get_Nlens(){
	return this->Nlens;
}

NTL::ZZ Paillier::PublicKey::get_Hs(){
	return this->Hs;
}

vector<NTL::ZZ> &Paillier::PublicKey::get_vec(){
	return this->vec;
}


// NTL::ZZ Paillier::PublicKey::get_N_square(){
// 	return this->N_square;
// }

Paillier::Encryptor::Encryptor(const PublicKey& pk): m_pk(pk){
	// ... 
}

void Paillier::Encryptor::encrypt(const HEnc::PTxt& pt, HEnc::CTxt& ct){
	// Generate a random value r
	NTL::ZZ r; //  1 < r < N
	while(true){
		r = NTL::RandomBnd(m_pk.get_N());
		if (NTL::GCD(r, m_pk.get_N()) == 1 && r > 1)
			break;
	}

	NTL::ZZ a;
	NTL::RandomLen(a, (m_pk.get_Nlens() + 1) / 2);

	// Encrypt message m
	NTL::ZZ tmp, c, m;
	tmp = 1;
	m = pt.get_pt();

	// clock_t start, end;
	// start = clock();
	// tmp = NTL::PowerMod(m_pk.get_Hs(), a, m_pk.get_N() * m_pk.get_N());
	// end = clock();
	// std::cout<<"time1: "<<(double)(end-start)/CLOCKS_PER_SEC * 1000<<"ms"<<std::endl;

	tmp = 1;
	// start = clock();
	long i = 0;
	NTL::ZZ Nsq = m_pk.get_N() * m_pk.get_N();
	while(a != 0) {
		if((a & 1) == 1)	tmp = MulMod(tmp, m_pk.get_vec()[i], Nsq);
		a = a >> 1;
		i++;
	}
	// end = clock();
	// std::cout<<"time2: "<<(double)(end-start)/CLOCKS_PER_SEC * 1000<<"ms"<<std::endl;

	NTL::mul(c, m, m_pk.get_N());
	c = NTL::AddMod(c, 1, m_pk.get_N() * m_pk.get_N());
	c = NTL::MulMod(tmp, c, m_pk.get_N() * m_pk.get_N());
	ct.set_ct(c);
}

void Paillier::Encryptor::he_add(const HEnc::CTxt& ct1, const HEnc::CTxt& ct2, HEnc::CTxt& ct){
	NTL::ZZ c1, c2, c;
	c1 = ct1.get_ct();
	c2 = ct2.get_ct();
	
	c = NTL::MulMod(c1, c2, m_pk.get_N() * m_pk.get_N());
	
	ct.set_ct(c);
}

void Paillier::Encryptor::he_add(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct){
	HEnc::CTxt pt1_ct;
	
	this->encrypt(pt1, pt1_ct);
	this->he_add(ct1, pt1_ct, ct);
}

void Paillier::Encryptor::he_add(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct){
	this->he_add(ct1, pt1, ct);
}

void Paillier::Encryptor::he_mul(const HEnc::CTxt& ct1, const HEnc::PTxt& pt1, HEnc::CTxt& ct){
	NTL::ZZ c1, m1, c;
	c1 = ct1.get_ct();
	m1 = pt1.get_pt();
	
	c = NTL::PowerMod(c1, m1, m_pk.get_N() * m_pk.get_N());
	
	ct.set_ct(c);
}

void Paillier::Encryptor::he_mul(const HEnc::PTxt& pt1, const HEnc::CTxt& ct1, HEnc::CTxt& ct){
	this->he_mul(ct1, pt1, ct);
}

Paillier::Decryptor::Decryptor(const SecretKey& sk): m_sk(sk){
	// ...
}

void Paillier::Decryptor::decrypt(const HEnc::CTxt& ct, HEnc::PTxt& pt){
	NTL::ZZ tmp, c, m;
	c = ct.get_ct();
	tmp = NTL::PowerMod(c, m_sk.get_phi_N(), m_sk.get_N() * m_sk.get_N());
	tmp -= 1;
	NTL::divide(tmp, tmp, m_sk.get_N());
	m = NTL::MulMod(tmp, m_sk.get_phi_N_inv(), m_sk.get_N());
	pt.set_pt(m);
}

void Paillier::key_gen(SecretKey& sk, PublicKey& pk, long bitlens){
	// Generate two random prime numbers
	NTL::ZZ p, q;
	
	rsa_param(p, q, bitlens);
	
	// Generate key pair
	SecretKey skey(p, q);
	PublicKey pkey(p*q, 2 * bitlens);
	
	sk = skey;
	pk = pkey;
	
}
