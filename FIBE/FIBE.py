from inspect import Parameter
from xml.dom.minidom import Element
from pypbc import *

def getSameSet(S, W):
    res = S.copy()
    res.intersection_update(W)
    return res

def lagrange(I, xi):              #计算拉格朗日因子
    res = Element.one(pairing, Zr)
    zeronum = Element.zero(pairing, Zr)
    xi = Element(pairing, Zr, xi)
    for xj in I:
        xj = Element(pairing, Zr, xj)
        if xi != xj:
            # res = Element(pairing, Zr, value = res * (zeronum - coef[j]))
            res = Element(pairing, Zr, value = res * (zeronum - xj) / (xi - xj))
    return res

def coefCal(pairing, coef, x):
    # 计算d - 1次多项式, 运算需要在Zr群上进行
    res = Element(pairing, Zr, coef[0])
    for i in range(1, len(coef)):
        val = Element(pairing, Zr, value = x ** i)
        res = Element(pairing, Zr, value = res + coef[i] * val)
    return res

def Setup(params, U):
    pairing = Pairing(params)
    g = Element.random(pairing, G1)

    msk = {}        # 主密钥组件包括[t1, t2, ..., tU, y]
    pk = {}         # 公钥组件包括[T1, T2, ..., TU, Y]
    for val in U.values():
        t = Element.random(pairing, Zr)
        g_t = Element(pairing, G1, value = g ** t)
        msk[val] = t
        pk[val] = g_t

    y = Element.random(pairing, Zr)
    egg = pairing.apply(g, g)
    Y = Element(pairing, GT, value = egg ** y)
    msk[-1] = y
    pk[-1] = Y

    return pairing, msk, pk, g

def KeyGen(pairing, msk, pk, S, d, g):
    # 构造一个d - 1次多项式, 系数随机, 但要满足f(0) = y
    y = msk[-1]         # msk的-1项对应的就是y
    coef = [y]
    for i in range(1, d):
        coef.append(Element.random(pairing, Zr))
    
    # 对于用户属性集合中的每一个属性i, 计算f(i)的值
    fval = {}
    for val in S:
        fval[val] = coefCal(pairing, coef, val)
    
    # 计算用户私钥
    sk = {}
    for val in S:
        res = Element(pairing, Zr, fval[val] / msk[val])
        sk[val] = Element(pairing, G1, g ** res)
    
    return sk, coef

def Encrypt(pairing, message, pk, W):
    # 选取随机数s, 计算E' = M * Y ^ s
    s = Element.random(pairing, Zr)

    Y_s = Element(pairing, GT, value = pk[-1] ** s)
    E_ = Element(pairing, GT, value = message * Y_s)
    E = {}
    for val in W:
        E[val] = Element(pairing, G1, value = pk[val] ** s)
    
    ct = [E_, E]
    return ct

def Decrypt(pairing, d, ct, sk, I):
    Plist = []
    for val in I:                   # 计算Pi = e(Ei, Di) ^ ci(0), ci(0)是拉格朗日因子
        Ei = ct[1][val]
        Di = sk[val]
        ci = lagrange(I, val)
        egg = pairing.apply(Ei, Di)
        P = Element(pairing, GT, value = egg ** ci)
        Plist.append(P)
    
    M = ct[0]
    for i in range(0, len(Plist)):
        M = Element(pairing, GT, value = M / Plist[i])
    return M

def getSet(UsrId, TextId):
    UsrId = list(set(UsrId))        # 对列表进行去重
    TextId = list(set(TextId))
    UsrId.sort()                    # 这里排下序
    TextId.sort()
    S = set()
    W = set()
    cnt = 1         # 不能从0开始编号！！！
    Udic = {}
    for i in range(0, len(UsrId)):
        Udic[UsrId[i]] = cnt
        S.add(cnt)
        cnt += 1
    
    for i in range(0, len(TextId)):
        if TextId[i] in Udic:
            W.add(Udic[TextId[i]])
        else:
            Udic[TextId[i]] = cnt
            W.add(cnt)
            cnt += 1
    return Udic, S, W

if __name__ == "__main__":

    q1 = get_random_prime(60)
    q2 = get_random_prime(60)
    params = Parameters(n = q1 * q2)

    # UsrId = ["0"]
    # TextId = ["0"]
    # UsrId = ["0", "1"]
    # TextId = ["0", "2"]
    UsrId = ["Alice", "Female", "20", "18866661302", "Alice@qq.com"]
    TextId = ["Bob", "Male", "20", "18866661302", "Alice@qq.com"]
    # S表示用户属性集合, W表示明文属性集合
    U, S, W = getSet(UsrId, TextId)
    print("S: {} \nW: {}".format(S, W))

    d = 3       # d表示系统门限值

    pairing, msk, pk, g = Setup(params, U)          # U表示全部属性集合
    sk, coef = KeyGen(pairing, msk, pk, S, d, g)

    tmpg = Element.random(pairing, G1)
    message = pairing.apply(tmpg, tmpg)
    print("plaintext:", message)
    
    ct = Encrypt(pairing, message, pk, W)

    I = getSameSet(S, W)         # 获取交集
    print("I:", I)
    #if len(I) >= d:
    M = Decrypt(pairing, d, ct, sk, I)
    print("decrypted ciphertext:", M)
    if(M.__eq__(message)):
        print("yes")
    else:
        print("no")
    # else:
    #     print("unable to decrypt")