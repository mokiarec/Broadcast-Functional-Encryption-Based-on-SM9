from pypbc import *
import time

from CryptoSystem import CryptoSystem, Crypto_decrypt, Crypto_encrypt

if __name__ == '__main__':
    start_time = time.time()
    # 初始化系统     应该确保向量长度n大于等于S的大小
    crypto = CryptoSystem(1, 3)

    # 密钥生成
    ID0 = "user1@example.com"
    ID1 = "user2@example.com"
    ID2 = "user3@example0.com"
    ID_set = [ID0, ID1, ID2]  # 接受者ID列表，此时有3个
    vector_x = [Element.random(crypto.mpk['BG'], Zr) for _ in range(crypto.mpk['n'])]  # 要加密的信息
    vector_y = [[Element.random(crypto.mpk['BG'], Zr) for _ in range(crypto.mpk['n'])] for _ in range(3)]  # 用户向量

    sk_id0 = crypto.key_gen(ID0, vector_y[0])
    sk_id1 = crypto.key_gen(ID1, vector_y[1])
    sk_id2 = crypto.key_gen(ID2, vector_y[2])

    print("-----------------------------------")
    print(f"所有的用户ID: {ID_set}")
    print(f"所有的用户向量S: {vector_y}")
    print(f"待加密的信息x： {vector_x}")

    # 加密
    ciphertext = Crypto_encrypt(vector_x, crypto.mpk,  ID_set)

    # ---用户0---
    # 解密
    decrypted_inner_product = Crypto_decrypt(crypto.mpk, ciphertext, ID_set, sk_id0, vector_y[0])

    # 预期
    inner_product_x_y = Element(crypto.mpk['BG'], Zr,
                                sum(int(a) * int(b) for a, b in zip(vector_x, vector_y[0])))
    target = crypto.mpk['BG'].apply(crypto.mpk['g'], crypto.mpk['h']) ** inner_product_x_y

    print(f"*当前用户0: {ID0} (用户ID) 和 {vector_y[0]} (用户向量y_j)")
    print(f"计算得到的内积:\t{decrypted_inner_product}")
    print(f"预期内积:\t\t{target}")

    # ---用户1---
    # 解密
    decrypted_inner_product = Crypto_decrypt(crypto.mpk, ciphertext, ID_set, sk_id1, vector_y[1])

    # 预期
    inner_product_x_y = Element(crypto.mpk['BG'], Zr,
                                sum(int(a) * int(b) for a, b in zip(vector_x, vector_y[1])))
    target = crypto.mpk['BG'].apply(crypto.mpk['g'], crypto.mpk['h']) ** inner_product_x_y

    print(f"*当前用户1: {ID1} (用户ID) 和 {vector_y[1]} (用户向量y_j)")
    print(f"计算得到的内积:\t{decrypted_inner_product}")
    print(f"预期内积:\t\t{target}")

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"加解密程序运行时间：{elapsed_time:.6f} 秒")