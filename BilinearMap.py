from xml.dom.minidom import Element
from pypbc import *

q_1 = get_random_prime(60)              # 定义两个长度为60bit的素数
q_2 = get_random_prime(60)

params = Parameters(n = q_1 * q_2)      # 生成椭圆曲线参数

pairing = Pairing(params)               # 根据参数构造双线性对

g = Element.random(pairing, G1)         # 取一个G1群中的元素g
print("g:", g)

a = Element.random(pairing, Zr)         # 取Zr群中的两个元素
b = Element.random(pairing, Zr)

print("a:{} b:{}".format(a, b))

g_a = Element(pairing, G1, value = g ** a)              # 计算g ^ a与g ^ b, 返回结果是G1群中的元素
g_b = Element(pairing, G1, value = g ** b)
print("g_a:{} g_b:{}".format(g_a, g_b))

egg_ab = pairing.apply(g_a, g_b)                        # 计算e(g ^ a, g ^ b)
print("egg_ab: ", egg_ab)

egg = pairing.apply(g, g)                               # 计算e(g, g)
ab = Element(pairing, Zr, value = a * b)                # 计算a * b, 结果依然在Zr群中
print("egg: {} ab: {}".format(egg, ab))

egg_ab_p = Element(pairing, GT, value = egg ** ab)      # 双线性映射：G1 * G1 -> GT, 得到e(g, g) ^ (a * b)
print("egg_ab_p: ", egg_ab_p)


if(egg_ab_p.__eq__(egg_ab)):        # 验证e(g ^ a, g ^ b)与e(g, g) ^ (a * b)相等
    print("yes")
else:
    print("no")

g = Element.zero(pairing, G1)
eg = pairing.apply(g, g)
print(eg)