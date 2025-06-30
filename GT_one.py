from pypbc import *

# 初始化配对参数
params = Parameters( qbits=128, rbits=128)
pairing = Pairing(params)

# 获取 GT 群的单位元
one = Element.one(pairing, GT)
print("GT单位元:", one)

# A 和 B 分别是 G1 群和 G2 群的两个元素
A = Element.random(pairing, G1)
B = Element.random(pairing, G2)

# D 是 GT 群中的一个元素
D = pairing.apply(A, B)
print("D:", D)

# 求 D 的逆元
D_inv = one
D_inv //= D
print("D 的逆元:", D_inv)

# 计算 D * D_inv
D_mul = D * D_inv

print("D * D_inv:", D_mul)
print("D * D_inv 是否等于单位元:", D_mul == one)

# 验证 D * D_inv 是否等于单位元
assert D_mul == one, "D * D_inv 不等于单位元"