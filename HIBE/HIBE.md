&emsp;&emsp;在HIBE中, ID用向量表示, 一个k维向量代表这个ID处在第k层。主密钥是在第0层的向量。我们假设系统最大深度是$l$。

**Setup:**
&emsp;&emsp;选取生成元$g \in G$, 选取一个随机的$\alpha \in Z_p$, 并令$g_1 = g^\alpha$。随后选取随机元素$g_2, g_3, h_1, ..., h_l \in G$。那么公共参数和主密钥就是

$$params = (g, g_1, g_2, g_3, h_1, ..., h_l), masterkey = g_2^\alpha$$

**KeyGen:**
&emsp;&emsp;为$ID = (I_1, ..., I_k) \in (Z_p^*)^k$生成私钥$d_{ID}$, 我们选取一个随机元素$r \in Z_p$并得到

$$d_{ID} = (g_2^\alpha * (h_1^{I_1}\cdots h_k^{I_{k}} * g_3) ^ r, g^r, h_{k+1}^r, ..., h_l^r)$$

&emsp;&emsp;我们可以直接构造第k层的私钥， 但我们也可以通过第k -1层的私钥来构造第k层的私钥。具体方法如下：

&emsp;&emsp;对于第k-1层的私钥

$$d_{ID|k-1} = (g_2^\alpha * (h_1^{I_1} \cdots h_{k-1}^{I_{k-1}}*g_3) ^ {r^{'}}, g ^ {r ^ {'}}, h_k^{r ^ {'}}, \ldots, h_l^{r ^ {'}}) = (a_0, a_1, b_k, \ldots, b_l)$$

&emsp;&emsp;我们随机选取$r = r ^ {'} + t \in Z_p$,构造$d_{ID}$:

$$d_{ID} = (a_0 * b_k^{I_k}*(h_1^{I_1} \cdots h_k^{I_k} * g_3) ^ t, a_1 * g_t, b_{k+1}*h_{k+1}^t, \ldots, b_l * h_l^t)$$

&emsp;&emsp;这样就能构造出$d_{ID}$。

**Encrypt:**
&emsp;&emsp;对于k层ID, 我们的明文$M \in G_1$, 我们选取随机元素$s \in Z_p$, 于是得到密文：

$$CT = (e(g_1, g_2) ^ s * M, g ^ s, (h_1^{I_1} \cdots h_k^{I_k} * g_3) ^ s) \in G_1 * G^2$$

**Decrypt:**
&emsp;&emsp;对于k层ID, 为了解密密文$CT = (A, B, C)$, 我们使用私钥$d_{ID} = (a_0, a_1, b_{k+1}, \ldots, b_l)$, 可以解密密文：

$$A * e(a_1, C) / e(B, a_0) = M$$

&emsp;&emsp;事实上, 我们容易推出：

$$\frac{e(a_1, C)}{e(B, a_0)} = \frac{e(g^r, (h_1^{I_1} \cdots h_k^{I_k} * g_3) ^ s)}{e(g ^ s, g_2^{\alpha}(h_1^{I_1} \cdots h_k^{I_k} * g_3) ^r)} = \frac{1}{e(g, g_2) ^ {s\alpha}} = \frac{1}{e(g_1, g_2) ^ s}$$