from xml.dom.minidom import Element
from pypbc import *

def Setup(pairing, l):
    # 构造公共参数与主密钥
    g = Element.random(pairing, G1)
    a = Element.random(pairing, Zr)
    g1 = Element(pairing, G1, value = g ** a)
    g2 = Element.random(pairing, G1)
    g3 = Element.random(pairing, G1)
    publicParams = [g, g1, g2, g3]
    for i in range(0, l):
        h = Element.random(pairing, G1)
        publicParams.append(h)
    msk = Element(pairing, G1, value = g2 ** a)

    return publicParams, msk

def KeyGen(pairing, l, k, msk, publicParams, IDlist):
    # 对于第k层用户, 其私钥为长度为l - k + 2的向量
    d_ID = []
    r = Element.random(pairing, Zr)

    # 首先构造私钥的第一项
    d00 = msk                   # 第一项分为前半部分和后半部分
    d01 = publicParams[3]       # 取g3
    for i in range(0, k):
        # 从索引为4处开始才是h
        h_I = Element(pairing, G1, value = publicParams[i + 4] ** IDlist[k][i])
        d01 = Element(pairing, G1, value = d01 * h_I)
    d01 = Element(pairing, G1, value = d01 ** r)
    d0 = Element(pairing, G1, value = d00 * d01)
    d_ID.append(d0)

    # 下面构造第二项g ^ r
    g_r = Element(pairing, G1, value = publicParams[0] ** r)
    d_ID.append(g_r)

    # 最后构造剩下的l - k项
    for i in range(0, l - k):
        # h_{k + 1}从publicParams的第k + 5项开始
        h_r = Element(pairing, G1, value = publicParams[k + 4 + i] ** r)
        d_ID.append(h_r)
    
    return d_ID

def Encrypt(pairing, l, k, message, publicParams, IDlist):
    # 从Zr中随机选取s
    s = Element.random(pairing, Zr)

    # 密文共有三项, 首先构造第一项
    egg = pairing.apply(publicParams[1], publicParams[2])
    egg = Element(pairing, GT, value = egg ** s)
    CT0 = Element(pairing, GT, value = egg * message)

    # 构造第二项g ^ s
    CT1 = Element(pairing, G1, value = publicParams[0] ** s)

    # 构造最后一项
    CT2 = publicParams[3]       # g3
    for i in range(0, k):
        h_I = Element(pairing, G1, value = publicParams[i + 4] ** IDlist[k][i])
        CT2 = Element(pairing, G1, value = CT2 * h_I)
    CT2 = Element(pairing, G1, value = CT2 ** s)

    CT = [CT0, CT1, CT2]
    return CT

def Decrypt(pairing, l, k, CT, d_ID):
    M = CT[0]
    eaC = pairing.apply(d_ID[1], CT[2])
    eBa = pairing.apply(CT[1], d_ID[0])
    M = M * eaC / eBa
    return M

if __name__ == "__main__":
    q1 = get_random_prime(60)
    q2 = get_random_prime(60)

    params = Parameters(n = q1 * q2)
    pairing = Pairing(params)

    # 设置最大深度l, 选取的k值, 明文从GT群中选取
    l = 5
    k = 2
    tmpg = Element.random(pairing, G1)
    message = pairing.apply(tmpg, tmpg)
    print(message)

    # 构造每层的ID
    vec = []
    IDlist = [[]]
    for i in range(0, l):
        I = Element.random(pairing, Zr)
        vec.append(I)

    for i in range(1, l + 1):
        IDlist.append([])
        for j in range(1, i + 1):
            IDlist[i].append(vec[j - 1])

    # 开始执行算法
    publicParams, msk = Setup(pairing, l)
    d_ID = KeyGen(pairing, l, k, msk, publicParams, IDlist)
    CT = Encrypt(pairing, l, k, message, publicParams, IDlist)
    M = Decrypt(pairing, l, k, CT, d_ID)

    print(M)
    if(M.__eq__(message)):
        print("yes")
    else:
        print("no")
