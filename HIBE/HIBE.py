
from pypbc import *
from collections import deque

class User:
    ID = []             # 每个用户都有一个ID
    k = 0               # 用户所在层数
    dID = []            # 用户私钥
    name = ""           # 用户名
    children = {}       # 由这个用户派生出来的用户
    def __init__(self, id, curk, sk, usrname):
        self.ID = id
        self.k = curk
        self.dID = sk
        self.name = usrname
        self.children = {}


    def insert(self, nameList) -> None:
        node = self
        nID = []
        nk = 0
        ndID = []
        for uname in nameList:
            if uname not in node.children:
                num = Element.from_hash(pairing, Zr, uname)
                if nk == 0:
                    nID.append(num)
                    ndID = KeyGen(pairing, l, 1, msk, publicParams, [num])
                    nUsr = User(nID, 1, ndID, uname)
                    node.children[uname] = nUsr
                else:
                    node.children[uname] = node.createNextSk(pairing, l, msk, publicParams, uname)
            node = node.children[uname]
            nk += 1


    # 用户可以用此函数构造下一层某个用户的私钥
    def createNextSk(self, pairing, l, msk, publicParams, uname):
        # 最后一层用户不能再构造私钥, 第一层用户采用方法一构造
        if(self.k == l or l == 0):
            return 
        # 将用户的名字映射为Zr上的元素, 得到新用户ID
        newI = Element.from_hash(pairing, Zr, uname)
        newID = self.ID.copy()
        newID.append(newI)
        
        t = Element.random(pairing, Zr)
        newdID = []
        # 本层用户私钥长度为l - k + 2, 新用户私钥长度为l - k + 1
        # 首先构造新用户私钥的第一项
        newdID00 = Element(pairing, G1, value = self.dID[0])
        newdID00 = Element(pairing, G1, value = newdID00 * (self.dID[2] ** newI))

        newdID01 = Element(pairing, G1, value = publicParams[3])
        for i in range(0, len(newID)):
            newdID01 = Element(pairing, G1, value = newdID01 * (publicParams[i + 4] ** newID[i]))
        newdID01 = Element(pairing, G1, value = newdID01 ** t)

        newdID.append(Element(pairing, G1, value = newdID00 * newdID01))

        # 现在构造第二项
        newdID1 = self.dID[1]
        newdID1 = Element(pairing, G1, value = newdID1 * (publicParams[0] ** t))
        
        newdID.append(newdID1)

        # 构造剩下的项
        for i in range(3, len(self.dID)):
            tmp = Element(pairing, G1, value = self.dID[i] * (publicParams[len(newID) + 1 + i] ** t))
            newdID.append(tmp)
        
        newUsr = User(newID, self.k + 1, newdID, uname)
        return newUsr

    # 判断某个用户是否在树中, 如果存在, 返回用户结点, 否则为空
    def isExist(self, nameList):
        node = self
        for uname in nameList:
            if uname not in node.children:
                print("The user does not exist")
                return None
            else:
                node = node.children[uname]
        return node

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

def KeyGen(pairing, l, k, msk, publicParams, ID):
    # 对于第k层用户, 其私钥为长度为l - k + 2的向量
    d_ID = []
    r = Element.random(pairing, Zr)

    # 首先构造私钥的第一项
    d00 = msk                   # 第一项分为前半部分和后半部分
    d01 = publicParams[3]       # 取g3
    for i in range(0, k):
        # 从索引为4处开始才是h
        h_I = Element(pairing, G1, value = publicParams[i + 4] ** ID[i])
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

def Encrypt(pairing, l, k, message, publicParams, ID):
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
        h_I = Element(pairing, G1, value = publicParams[i + 4] ** ID[i])
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

# 使用BFS遍历结点树
def BFS(root : User):
    if root == None:
        return 
    LenRes = []
    NameRes = []
    que = deque([root])
    while(len(que) > 0):
        size = len(que)
        LenTmp = []
        NameTmp = []
        for _ in range(0, size):
            node = que.popleft()
            if(node == None):
                continue
            LenTmp.append(len(node.dID))
            NameTmp.append(node.name)
            for key in node.children.keys():
                que.append(node.children[key])
        LenRes.append(LenTmp)
        NameRes.append(NameTmp)
    return LenRes, NameRes

if __name__ == "__main__":
    q1 = get_random_prime(60)
    q2 = get_random_prime(60)

    params = Parameters(n = q1 * q2)
    pairing = Pairing(params)

    # 设置最大深度l, 明文从GT群中选取
    l = 5
    tmpg = Element.random(pairing, G1)
    message = pairing.apply(tmpg, tmpg)
    print("plaintext:\n", message)


    # 开始执行算法
    # 首先构造出公共参数与主密钥
    publicParams, msk = Setup(pairing, l)

    # 根结点什么都没有, 即第零层
    rootUsr = User([], 0, [], "")
    # 第一层用户的私钥由主密钥得来, 因此不能用第二种方法构造私钥
    rootUsr.insert(["China"])
    
    # 先在第二层声明两个结点
    rootUsr.insert(["China", "Beijing"])
    rootUsr.insert(["China", "HuNan"])
    
    # 在第三层声明四个结点
    rootUsr.insert(["China", "Beijing", "HaiDian"])
    rootUsr.insert(["China", "Beijing", "DaXing"])
    rootUsr.insert(["China", "HuNan", "ChangSha"])
    rootUsr.insert(["China", "HuNan", "XiangTan"])

    LenRes, NameRes = BFS(rootUsr)
    print("the length of private key:\n", LenRes)
    print("the name of users:\n", NameRes)

    # 使用长沙进行加密
    cs = rootUsr.isExist(["China", "HuNan", "ChangSha"])
    CT = Encrypt(pairing, l, cs.k, message, publicParams, cs.ID)

    print("the length of ciphertext:\n", len(CT))
    # 使用长沙进行解密
    # M = Decrypt(pairing, l, cs.k, CT, cs.dID)

    # 使用海淀进行解密
    hd = rootUsr.isExist(["China", "Beijing", "HaiDian"])
    # hd = rootUsr.isExist(["China", "HuNan", "ChangSha"])
    if hd == None:
        exit()
    
    M = Decrypt(pairing, l, hd.k, CT, hd.dID)

    print("decrypted ciphertext:\n", M)
    if(M.__eq__(message)):
        print("yes")
    else:
        print("no")