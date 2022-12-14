from pypbc import *
from collections import deque
from WriteReadFile import *


class User:
    k = 0               # 用户所在层数
    name = ""           # 用户名
    FullName = ""       # 从根节点到这个结点的全部用户名
    children = {}       # 由这个用户派生出来的用户
    
    
    def __init__(self, curk, usrName, FullName):
        self.k = curk
        self.name = usrName
        self.FullName = FullName
        self.children = {}


    def insert(self, nameList):
        node = self
        nk = 0
        for uname in nameList:
            if uname not in node.children:
                num = Element.from_hash(pairing, Zr, uname)
                if nk == 0:
                    # 将ID写入文件中
                    WriteID(pairing, uname, [num])
                    # 生成用户私钥
                    self.KeyGen(pairing, l, [num], uname)
                    nUsr = User(1, uname, uname)
                    node.children[uname] = nUsr
                else:
                    node.children[uname] = node.createNextSk(pairing, l, uname)
            node = node.children[uname]
            nk += 1
        return


    # 用户可以用此函数构造下一层某个用户的私钥
    def createNextSk(self, pairing, l, uname):
        # 读取主密钥, 公共参数, ID与私钥
        msk = ReadMsk(pairing)
        publicParams = ReadPublicParams(pairing)
        ID = ReadID(pairing, self.FullName)
        dID = ReadSk(pairing, self.FullName)

        # 最后一层用户不能再构造私钥, 第一层用户采用方法一构造
        if(self.k == l or l == 0):
            return 
        
        # 将用户的名字映射为Zr上的元素, 得到新用户ID
        newI = Element.from_hash(pairing, Zr, uname)
        newID = ID.copy()
        newID.append(newI)
        
        t = Element.random(pairing, Zr)
        newdID = []
        # 本层用户私钥长度为l - k + 2, 新用户私钥长度为l - k + 1
        # 首先构造新用户私钥的第一项
        newdID00 = Element(pairing, G1, value = dID[0])
        newdID00 = Element(pairing, G1, value = newdID00 * (dID[2] ** newI))

        newdID01 = Element(pairing, G1, value = publicParams[3])
        for i in range(0, len(newID)):
            newdID01 = Element(pairing, G1, value = newdID01 * (publicParams[i + 4] ** newID[i]))
        newdID01 = Element(pairing, G1, value = newdID01 ** t)

        newdID.append(Element(pairing, G1, value = newdID00 * newdID01))

        # 现在构造第二项
        newdID1 = dID[1]
        newdID1 = Element(pairing, G1, value = newdID1 * (publicParams[0] ** t))
        
        newdID.append(newdID1)

        # 构造剩下的项
        for i in range(3, len(dID)):
            tmp = Element(pairing, G1, value = dID[i] * (publicParams[len(newID) + 1 + i] ** t))
            newdID.append(tmp)

        newUsr = User(self.k + 1, uname, self.FullName + "-" + uname)

        # 将私钥, ID写入文件
        WriteSk(pairing, newUsr.FullName, newdID)
        WriteID(pairing, newUsr.FullName, newID)
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


    def Setup(self, pairing, l):
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

        # 将公共参数与主密钥写入文件中
        WritePublicParams(pairing, publicParams)
        WriteMsk(pairing, msk)

        return 


    def KeyGen(self, pairing, l, ID, uname):
        # 只有第零层才能用这种方法生成私钥
        if self.k > 0:
            return
        
        # 这里与论文的定义保持一致
        k = self.k + 1

        # 读取主密钥与公共参数
        msk = ReadMsk(pairing)
        publicParams = ReadPublicParams(pairing)

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
        
        # 将私钥写入文件中
        WriteSk(pairing, uname, d_ID)
        return 


    def Encrypt(self, pairing, l, message):
        # 读取公共参数, ID
        publicParams = ReadPublicParams(pairing)
        ID = ReadID(pairing, self.FullName)

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
        for i in range(0, self.k):
            h_I = Element(pairing, G1, value = publicParams[i + 4] ** ID[i])
            CT2 = Element(pairing, G1, value = CT2 * h_I)
        CT2 = Element(pairing, G1, value = CT2 ** s)

        CT = [CT0, CT1, CT2]

        # 将密文写入文件中
        WriteCT(pairing, self.FullName, CT)
        return CT


    def Decrypt(self, pairing, CT):
        # 读取私钥
        d_ID = ReadSk(pairing, self.FullName)

        M = CT[0]
        eaC = pairing.apply(d_ID[1], CT[2])
        eBa = pairing.apply(CT[1], d_ID[0])
        M = M * eaC / eBa

        # 将解密后的明文写入文件中
        WritePT(pairing, self.FullName, M)
        return M


    # 使用BFS遍历结点树
    def BFS(self):
        if self == None:
            return 
        NameRes = []
        que = deque([self])
        while(len(que) > 0):
            size = len(que)
            NameTmp = []
            for _ in range(0, size):
                node = que.popleft()
                if(node == None):
                    continue
                NameTmp.append(node.name)
                for key in node.children.keys():
                    que.append(node.children[key])
            NameRes.append(NameTmp)
        return NameRes


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
    # 根结点什么都没有, 即第零层
    rootUsr = User(0, "", "")
    rootUsr.Setup(pairing, l)
    
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

    # 遍历这棵树, 查看每个节点的名字
    NameRes = rootUsr.BFS()
    print("the name of users:\n", NameRes)

    rootUsr = rootUsr.children["China"]

    # 加密明文
    CT = rootUsr.Encrypt(pairing, l, message)
    print("the length of ciphertext:\n", len(CT))

    # rootUsr = rootUsr.children["Beijing"]

    # 解密密文
    M = rootUsr.Decrypt(pairing, CT)
    print("decrypted ciphertext:\n", M)

    if(M.__eq__(message)):
        print("yes")
    else:
        print("no")
