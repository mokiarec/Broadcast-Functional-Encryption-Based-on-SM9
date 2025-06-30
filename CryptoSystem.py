import hashlib
import time
import warnings
from pprint import pprint
from typing import Tuple, List

from sympy import symbols, prod, Poly, expand, cancel

from pypbc import *

warnings.filterwarnings("ignore", category=DeprecationWarning)

LogTag = 0  # 日志输出，为0时不打印输出，为1时打印输出

class CryptoSystem:
    def __init__(self, security_param: int, vector_length: int):
        """
        初始化加密系统
        """

        print_log(f"----- 加密系统 -----")
        self._security_param = security_param
        self._vector_length = vector_length
        # 生成双线性群参数
        self.__params = Parameters(qbits=64, rbits=16)  # qbits: 有限域Fq的位数（通常≥256）,rbits: 群阶的位数（影响密钥空间大小）
        # params = Parameters(qbits=512, rbits=160)  # qbits: 有限域Fq的位数（通常≥256）,rbits: 群阶的位数（影响密钥空间大小）
        self.__pairing = Pairing(self.__params)
        print_log(f"系统参数: { self.__params}------")

        # 获得生成元，每次都不同
        self.__g = Element.random(self.__pairing, G1)  # G1群
        self.__h = Element.random(self.__pairing, G2)  # G2群
        print_log(f"G1群的生成元: {self.__g}")
        print_log(f"G2群的生成元: {self.__h}")

        # 验证双线性对性质
        test_a = Element.random(self.__pairing, Zr)
        test_pbc1 = self.__pairing.apply(self.__g ** test_a, self.__h ** test_a)
        test_pbc2 = self.__pairing.apply(self.__g, self.__h) ** (test_a ** 2)
        print_log(f"验证双线性对性质: {test_pbc1 == test_pbc2}")

        # 随机选择秘密值
        self.__alpha = Element.random(self.__pairing, Zr)
        self.__beta = [Element.random(self.__pairing, Zr) for _ in range(vector_length)]
        self.__gamma1 = Element.random(self.__pairing, Zr)
        self.__gamma2 = Element.random(self.__pairing, Zr)
        self.__eta1 = Element.random(self.__pairing, Zr)
        self.__eta2 = self.__gamma1 * self.__eta1 * self.__gamma2 ** -1  # 保证 gamma1*eta1 = gamma2*eta2
        self.__r = 0  # 测试
        self._inner_product_beta_y = 0  # 测试
        print_log(f"alpha(Zp域):\t{self.__alpha}")
        print_log(f"beta(Zp^n扩域):\t {[element for element in self.__beta]}")
        print_log(f"gamma1(Zp域): \t{self.__gamma1}")
        print_log(f"gamma2(Zp域): \t{self.__gamma2}")
        print_log(f"eta1(Zp域): \t{self.__eta1}")
        print_log(f"eta2(Zp域): \t{self.__eta2}")
        # 添加调试输出
        # print_log("验证 γ₁η₁ == γ₂η₂:", (self._gamma1 * self._eta1) == (self._gamma2 * self._eta2))

        # 设置主公钥
        self.mpk = {
            'BG': self.__pairing,
            'n': vector_length,
            'H': CryptoSystem.hash_to_zp,
            'h': self.__h,
            'g': self.__g,
            'g_gamma1': self.__g ** self.__gamma1,
            'g_eta1*alpha*alpha': self.__g ** (self.__eta1 * self.__alpha ** 2),
            'g_gamma2*eta2*alpha': self.__g ** (self.__gamma2 * self.__eta2 * self.__alpha),
            'h_gamma1': self.__h ** self.__gamma1,
            'g_poly': [[
                self.__g ** (self.__eta1 * self.__alpha ** 2 * self.__beta[i]),
                self.__g ** (self.__gamma1 * self.__alpha ** (i + 1)),
                self.__h ** self.__beta[i],
                self.__h ** (self.__gamma1 * self.__alpha ** (i + 1)),
            ] for i in range(0, vector_length)]

        }
        pprint(f"mpk: {self.mpk}")

        # 设置主私钥
        self._msk = {
            'alpha': self.__alpha,
            'gamma1': self.__gamma1,
            'gamma2': self.__gamma2,
            'eta1': self.__eta1,
            'eta2': self.__eta2,
            'beta': self.__beta
        }
        pprint(f"msk: {self._msk}")


    @staticmethod
    def hash_to_zp(message: str, pairing: Pairing) -> Element:
        """将消息哈希到 Zp 域"""
        # 哈希字符串到字节
        hash_bytes = hashlib.sha256(message.encode()).digest()  # 32字节哈希

        # 将哈希映射到 Zr 群元素
        zr_element = Element.from_hash(pairing, Zr, hash_bytes)
        # print_log("Hash -> Zr element:", zr_element)

        return zr_element

    def key_gen(self, ID: str, vector_y_j: List[Element]) -> {}:
        """
        为指定身份和向量y生成私钥
        给定mpk, msk, ID, vector_y
        """
        print_log(f"----- 密钥产生 -----")
        if len(vector_y_j) != self._vector_length:
            raise ValueError("消息向量长度不匹配")
        print_log(f"y(Zp^n扩域): {vector_y_j}")

        k = Element.random(self.__pairing, Zr)  # 随机选择一个Zp域内的k
        print_log(f"k(Zp域): \t{k}")
        hash_id = CryptoSystem.hash_to_zp(ID, self.__pairing)

        # 计算K1和K2
        inner_product = Element(self.__pairing, Zr,
                                sum(int(yi) * int(bi) for yi, bi in zip(vector_y_j, self.__beta)))
        self._inner_product_beta_y = inner_product  # 测试
        K1 = self.__h ** (self.__eta1 * self.__alpha * ((inner_product - k) * (self.__alpha + hash_id) ** -1))
        K2 = k
        print_log(f"K1(群G2): \t{K1}")
        print_log(f"K2(Zp域): \t{K2}")

        sk_id = {
            'K1': K1,
            'K2': K2,
            'ID': ID
        }

        return sk_id

    def generate_y(self):
        return [Element.random(self.__pairing, Zr) for _ in range(0, self._vector_length)]


def Crypto_encrypt(vector_x: List[Element], mpk: dict, S: List[str]) -> dict:
    """
    加密消息向量
    给定mpk, S, vector_x
    S是授权者集合
    """

    # 从主公钥mpk解析信息
    g = mpk['g']
    h = mpk['h']
    pairing = mpk['BG']
    n = mpk['n']
    Hash = mpk['H']
    g_1 = mpk['g_gamma1']
    g_2 = mpk['g_eta1*alpha*alpha']
    g_3 = mpk['g_gamma2*eta2*alpha']
    g_poly = mpk['g_poly']

    print_log(f"----- 加密 -----")
    if len(vector_x) != n:
        raise ValueError("消息向量长度不匹配")

    r = Element.random(pairing, Zr)

    # 计算C0
    alpha = symbols('alpha')
    H = [Hash(message=ID, pairing=pairing) for ID in S]
    product = prod([(alpha + H[i]) for i in range(S.__len__())])
    product = Poly(product, alpha)
    coeffs = product.all_coeffs()

    C0 = Element.one(pairing, G1)
    for power, coeff in enumerate(reversed(coeffs)):
        if power == 0:
            # 常数项
            term = g_1 ** int(coeff)
        else:
            # 高次项
            h_alpha_i = g_poly[power - 1][1]
            term = h_alpha_i ** int(coeff)

        # 累乘结果
        C0 = C0 * term
    C0 = C0 ** r

    # 计算C1和C2
    C1 = pairing.apply(g_3, h) ** r  # 计算双线性对
    C2 = g_2 ** r
    print_log(f"C0(群G1): {C0}")
    print_log(f"C1(群GT): {C1}")
    print_log(f"C2(群G1): {C2}")

    # 计算C(i, 1)和C(i, 2)
    C_t1 = list()
    C_t2 = list()
    for i in range(n):
        C_t1.append(g_poly[i][0] ** -r)
        C_t2.append(pairing.apply(g_3, g_poly[i][2]) ** r * pairing.apply(g, h) ** vector_x[i])

    CT = {
        'C0': C0,
        'C1': C1,
        'C2': C2,
        'Ct_1': C_t1,
        'Ct_2': C_t2,
        'S': S
    }
    print_log(f"CT: {CT}")

    return CT


def Crypto_decrypt(mpk: dict, CT: dict, S: List[str], sk_id: dict, y_j: []) -> int:
    """
    解密密文
    给定mpk, CT, S, SK_id, vector_y_j（在SK_id中）
    """
    # 从身份sk_id获得信息

    print_log(f"----- 解密 -----")
    if sk_id['ID'] not in CT['S']:
        raise ValueError("身份不在接收者集合中")
    K1 = sk_id['K1']
    K2 = sk_id['K2']

    # 从主公钥mpk解析信息
    g = mpk['g']
    h = mpk['h']
    pairing = mpk['BG']
    n = mpk['n']
    Hash = mpk['H']
    g_1 = mpk['g_gamma1']
    g_2 = mpk['g_eta1*alpha*alpha']
    g_3 = mpk['g_gamma2*eta2*alpha']
    g_poly = mpk['g_poly']

    # 从消息CT获得信息
    C0 = CT['C0']
    C1 = CT['C1']
    C2 = CT['C2']
    Ct_1 = CT['Ct_1']
    Ct_2 = CT['Ct_2']

    # 计算当前用户的序号j
    j = 0
    for i in range(len(S)):
        if S[i] == sk_id['ID']:
            j = i
            break
    print_log(f"当前用户的序号j: {j}")

    # 计算Pi_Ct_1和Pi_Ct_2
    Pi_Ct_1 = Element.one(pairing, G1)  # 生成G1的单位元
    Pi_Ct_2 = Element.one(pairing, GT)  # 生成GT的单位元
    for i in range(n):
        Pi_Ct_1 = Pi_Ct_1 * Ct_1[i] ** y_j[i]
    for i in range(n):
        Pi_Ct_2 = Pi_Ct_2 * Ct_2[i] ** y_j[i]
    print_log(f"Pi_Ct_1(群G1): {Pi_Ct_1}")
    print_log(f"Pi_Ct_2(群GT): {Pi_Ct_2}")

    # 求多项式
    alpha = symbols('alpha')
    p_js, product = compute_polynomial(Hash, S, j, pairing)

    product2 = Element(pairing, Zr, product[1])

    # 求指数上的多项式
    h_p_j = compute_exponentiated_polynomial(mpk, poly=p_js, h_alpha_powers=g_poly, pairing=pairing)

    # 计算A和B
    A = pairing.apply(C0, K1) * pairing.apply(Pi_Ct_1, h_p_j)
    B = pairing.apply(C2 ** K2, h_p_j) * (C1 ** (K2 * product2))
    print_log(f"A(群GT): {A}")
    print_log(f"B(群GT): {B}")

    # 计算D
    D = (A * B) ** (product2 ** -1)

    print_log(f"D(群GT): {D}")

    D_inv = Element.one(mpk['BG'], GT)
    D_inv //= D
    result = Pi_Ct_2 * D_inv

    return result


def compute_polynomial(Hash, id_list: List[str], j, pairing: Pairing) -> Tuple[Poly, list]:
    """
    计算多项式 p_{j,S}(alpha) 的值

    参数:
        alpha_val: alpha 的具体数值
        id_list: 所有ID的列表 [ID_1, ID_2, ..., ID_s]的哈希函数
        j: 当前ID的索引（从1开始计数）
        gamma1: 常数 γ₁
    """
    alpha = symbols('alpha')
    s = len(id_list)

    # 计算哈希ID
    H_id_list = [int(Hash(ID, pairing)) for ID in id_list]

    # 计算连乘积部分
    product1 = prod([(alpha + H_id_list[i]) for i in range(s) if i != j])
    product2 = prod([H_id_list[i] for i in range(s) if i != j])
    product = [product1, product2]

    # 构造多项式并确保整除
    numerator = expand(product1 - product2)  # 展开多项式
    p_js_expr = cancel(numerator / alpha)  # 符号除法，自动约分
    print_log(f"p_js_expr(多项式): {p_js_expr}")

    # 转换为Poly对象（显式指定生成器alpha）
    p_js = Poly(p_js_expr, alpha)

    return p_js, product


def compute_exponentiated_polynomial(mpk: dict,
                                     poly: Poly,
                                     h_alpha_powers: dict,
                                     pairing: Pairing) -> Element:
    """
    计算 h^p(α)，其中 p(α) 是多项式，h_alpha_powers 包含 h^α^i 的值

    参数:
        h: 群元素 h ∈ G
        poly: SymPy 多项式对象 p(α)
        h_alpha_powers: 字典 {i: h^α^i}（i ≥ 1）
        pairing: Pairing 上下文（用于群运算）
    """
    alpha = symbols('alpha')
    coeffs = poly.all_coeffs()  # 获取系数 [c_n, ..., c_1, c_0]
    result = Element.one(pairing, G2)  # 初始化为群单位元

    # 从最高次项开始处理
    for power, coeff in enumerate(reversed(coeffs)):
        if power == 0:
            # 常数项 c0: h^c0
            term = (mpk['h_gamma1']) ** int(coeff)
        else:
            # 高次项 c_i*α^i: (h^α^i)^c_i
            h_alpha_i = h_alpha_powers[power - 1][3]
            term = h_alpha_i ** int(coeff)

        # 累乘结果
        result = result * term

    print_log(f"h上的多项式指数运算结果(群G2): {result}")
    return result

def print_log(*args, **kwargs) -> None:
    global LogTag
    if LogTag == 1:
        pprint(*args, **kwargs)