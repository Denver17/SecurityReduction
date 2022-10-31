&emsp;&emsp;下面是FIBE方案的过程:

**Setup**
&emsp;&emsp;首先, 我们定义属性集合全集的阶数$|U|$, 为了方便, 我们定义集合的编号为Zr群中的1~U。随后从Zr群中随机取U个元素$t_1, \ldots, t_{|U|}$。最后, 从Zr群中随机选取y,那么我们得到公共参数:

$$T_1 = g ^ {t_1}, \ldots, T_{|U|} = g ^ {t_{|U|}}, Y = e(g, g) ^ y$$

&emsp;&emsp;主密钥:

$$t_1, \ldots, t_{|U|}, y$$

**KeyGen**
&emsp;&emsp;为了生成某个身份$ \omega \subseteq U$, 我们首先随机选取一个d - 1次的多项式q, 但要满足$q(0) = y$。那么对于这个身份$\omega$中的每个属性i, 我们得到其对应的私钥构成:$(D_i)_{i \in \omega}$, 而$D_i = g^{\frac{q(i)}{t_i}}$。于是得到$\omega$的私钥D。

**Encryption**
&emsp;&emsp;我们使用公钥$\omega^{'}$对明文$M \in G_2$进行加密:
&emsp;&emsp;首先从ZR群中随机选取元素s, 那么密文可以由如下公式得到

$$ E = (\omega^{'}, E^{'} = MY^s, [E_i = T_i^s]_{i \in \omega^{'}})$$

**Decryption**
&emsp;&emsp;假设我们的密文是由身份$\omega^{'}$加密的, 我们使用身份$\omega$生成的私钥解密, 两个身份的交集阶数不小于d。我们从其交集中选取d个元素,设这个集合为S, 那么密文可以按如下方法解密:

$$ \frac{E^{'}}{\prod_{i \in S}(e(D_i, E_i))^{ci(0)}} = M$$

其中$ci(0)$是拉格朗日因子。