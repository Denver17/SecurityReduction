from pypbc import *
import dill
import pickle
import os

# 创建存储数据的文件夹
path = "./file/"
if not os.path.exists(path):
    os.makedirs(path)


# 将主密钥写入文件, 主密钥是一个Element对象, 所以直接写入
def WriteMsk(pairing, content):
    fileName = path + "Msk.txt"
    with open(fileName, "w") as f:
        f.write(str(content))


# 将公共参数写入文件, 公共参数是一个列表, 因此逐行写入
def WritePublicParams(pairing, content):
    fileName = path + "PublicParams.txt"
    res = ""
    for i in range(0, len(content)):
        res += str(content[i]) + "\n"
    with open(fileName, "w") as f:
        f.write(res)


# 将私钥写入文件, 私钥是一个列表, 逐行写入
def WriteSk(pairing, usrName, content):
    fileName = path + usrName + "-Sk.txt"
    res = ""
    for i in range(0, len(content)):
        res += str(content[i]) + "\n"
    with open(fileName, "w") as f:
        f.write(res)


# 将密文写入文件, 密文第一个是GT群元素, 后面两个是G1群元素
def WriteCT(pairing, usrName, content):
    fileName = path + usrName + "-CT.txt"
    res = ""
    for i in range(0, len(content)):
        res += str(content[i]) + "\n"
    with open(fileName, "w") as f:
        f.write(res)


# 将明文(经过解密的密文)写入文件
def WritePT(pairing, usrName, content):
    fileName = path + usrName + "-PT.txt"
    with open(fileName, "w") as f:
        f.write(str(content))


# 读取主密钥, 主密钥是G1群元素, 直接读取
def ReadMsk(pairing):
    fileName = path + "Msk.txt"
    with open(fileName, "r") as f:
        content = f.read()
    res = Element(pairing, G1, content)
    return res


# 读取公共参数
def ReadPublicParams(pairing):
    fileName = path + "PublicParams.txt"
    content = []
    for line in open(fileName):
        line = line[:-1]
        content.append(Element(pairing, G1, line))
    return content


# 读取私钥
def ReadSk(pairing, usrName):
    fileName = path + usrName + "-Sk.txt"
    content = []
    for line in open(fileName):
        line = line[:-1]
        content.append(Element(pairing, G1, line))
    return content


# 读取密文, 密文第一个是GT群元素, 后面两个是G1群元素
def ReadCT(pairing, usrName):
    fileName = path + usrName + "-CT.txt"
    content = []
    cnt = 0
    for line in open(fileName):
        line = line[:-1]
        if cnt == 0:
            content.append(Element(pairing, GT, line))
        else:
            content.append(Element(pairing, G1, line))
        cnt += 1
    return content


# 读取明文(经过解密的密文)
def ReadPT(pairing, usrName):
    fileName = path + usrName + "-PT.txt"
    with open(fileName, "r") as f:
        content = f.read()
    res = Element(pairing, GT, content)
    return res

