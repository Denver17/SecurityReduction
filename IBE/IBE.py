#from xml.dom.minidom import Element
from pypbc import *
import array

def Setup():
    x = Element.random(pairing, Zr)                     # 选取随机数x作为系统主密钥msk
    g = Element.random(pairing, G1)                     # 选取随机元素g作为生成元
    g_x = Element(pairing, G1, value = g ** x)          # 计算公共参数g ^ x
    # 现在我们得到系统公钥pk = <g, g ^ x>
    return x, g, g_x

def KeyGen(id, x):
    # 将用户id哈希为G1上的元素
    Qid = Element.from_hash(pairing, G1, id)
    # 计算私钥
    sk = Element(pairing, G1, value = Qid ** x)
    return sk

def Encrypt(id, M, g, g_x):
    # 将用户id映射为G1上的元素
    Qid = Element.from_hash(pairing, G1, id)
    # 在Zr中选取随机数r, 计算密文组件C1 = g ^ r
    r = Element.random(pairing, Zr)
    C1 = Element(pairing, G1, value = g ** r)
    # 计算g_id = e(Qid, g ^ x) ^ r
    egg_Qid_gx = pairing.apply(Qid, g_x)
    g_id = Element(pairing, GT, value = egg_Qid_gx ** r)
    
    # 计算密文组件C2 = M 异或 H2(g_id)
    # H2是哈希函数GT -> {0, 1} ^ n
    hash_gid = Element.from_hash(pairing, G1, str(g_id))   # 哈希到哪不太确定
    
    # 转化为bytearray然后异或
    hash_gid = bytearray(str(hash_gid).encode('ascii'))
    M = bytearray(M.encode('ascii'))
    C2 = bytearray(len(M))
    for i in range(0, len(M)):
        C2[i] = (M[i] ^ hash_gid[i])
    return C1, C2

def Decrypt(sk, C1, C2):
    g_id = pairing.apply(sk, C1)
    # 解密的关键在于恢复g_id
    hash_gid = Element.from_hash(pairing, G1, str(g_id))
    hash_gid = bytearray(str(hash_gid).encode('ascii'))
    
    M = bytearray(len(C2))
    for i in range(0, len(C2)):
        M[i] = (C2[i] ^ hash_gid[i])
    return str(M.decode('ascii'))

if __name__ == "__main__":
    idBob = "Bob@example.com"
    idAlice = "Alice@example.com"
    message = "hello world!"

    q1 = get_random_prime(60)
    q2 = get_random_prime(60)
    params = Parameters(n = q1 * q2)
    pairing = Pairing(params)
    
    x, g, g_x = Setup()
    # 目标id为Bob
    sk = KeyGen(idAlice, x)
    C1, C2 = Encrypt(idAlice, message, g, g_x)
    M = Decrypt(sk, C1, C2)

    print(M)