#include<iostream>
#include <exception>
#include <boost/program_options.hpp>
// #include<henc/paillier.h>
#include"paillier.h"
#include<ctime>
using namespace std;

namespace op = boost::program_options;

class User {
public:
    User(long bitlens, NTL::ZZ secret){
        this->secret = secret;
        Paillier::key_gen(this->sk, this->pk, bitlens);
    }
public:
    Paillier::SecretKey sk;
    Paillier::PublicKey pk;
    NTL::ZZ secret;
};

int main()
{
    cout<<"hello world"<<endl;

    long bitlens = 1024;

    NTL::ZZ secretA;
    secretA = 32352459;
    NTL::ZZ secretB;
    secretB = 4893276;
    User A(bitlens, secretA);
    User B(bitlens, secretB);

    Paillier::Encryptor enc(B.pk);
	Paillier::Decryptor dec(B.sk);

    // 1、B加密明文
    HEnc::PTxt pt_b;
	HEnc::CTxt ct_b;
    pt_b.set_pt(secretB);
    enc.encrypt(pt_b, ct_b);

    // 2、A处理明文a与密文b
    NTL::ZZ x, y;
	x = NTL::RandomLen_ZZ(32);
    y = NTL::RandomLen_ZZ(32);
    HEnc::PTxt mx, my;
    mx.set_pt(x);
    my.set_pt(y);

    HEnc::CTxt tmp_ct;
    enc.he_mul(ct_b, mx, tmp_ct);
    HEnc::CTxt ct_b_;
    enc.he_add(tmp_ct, my, ct_b_);

    NTL::ZZ tmp;
    tmp = NTL::MulMod(secretA, x, B.pk.get_N() * B.pk.get_N());
    NTL::ZZ tmp_a;
    tmp_a = NTL::AddMod(tmp, y, B.pk.get_N() * B.pk.get_N());
    HEnc::PTxt pt_a;
	HEnc::CTxt ct_a;
    pt_a.set_pt(tmp_a);
    enc.encrypt(pt_a, ct_a);

    // 3、B解密两个密文，比较大小
    HEnc::PTxt rt_a;
	dec.decrypt(ct_a, rt_a);

    HEnc::PTxt rt_b;
	dec.decrypt(ct_b_, rt_b);

    cout<<rt_a.get_pt()<<endl;
    cout<<rt_b.get_pt()<<endl;
    if(rt_a.get_pt() > rt_b.get_pt()) {
        cout<<"a > b"<<endl;
    }
    else if(rt_a.get_pt() < rt_b.get_pt()) {
        cout<<"a < b"<<endl;
    }
    else    cout<<"a == b"<<endl;

    NTL::ZZ resA, resB;
    resA = NTL::MulMod(secretA, x, B.pk.get_N() * B.pk.get_N());
    resA = NTL::AddMod(resA, y, B.pk.get_N() * B.pk.get_N());
    resB = NTL::MulMod(secretB, x, B.pk.get_N() * B.pk.get_N());
    resB = NTL::AddMod(resB, y, B.pk.get_N() * B.pk.get_N());
    if((rt_a.get_pt() == resA) && (rt_b.get_pt() == resB))      cout<<"correct"<<endl;
    else    cout<<"error"<<endl;

    return 0;
}

