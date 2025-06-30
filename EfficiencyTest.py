from pprint import pprint
import random

import matplotlib.pyplot as plt
import matplotlib
from pypbc import *
import time

from CryptoSystem import CryptoSystem, Crypto_decrypt, Crypto_encrypt

def EfficiencyTest(user_num: int):
    # 密钥生成

    ID_set = [f"user{i}@example.com" for i in range(user_num)]  # 接受者ID列表
    vector_x = [Element.random(crypto.mpk['BG'], Zr) for _ in range(crypto.mpk['n'])]  # 要加密的信息
    vector_y = [[Element.random(crypto.mpk['BG'], Zr) for _ in range(crypto.mpk['n'])] for _ in range(user_num)]  # 用户向量

    # pprint(f"所有的用户ID: {ID_set}")
    # pprint(f"所有的用户向量S: {vector_y}")
    # pprint(f"待加密的信息x： {vector_x}")

    # 加密
    ciphertext = Crypto_encrypt(vector_x, crypto.mpk, ID_set)

    # 收集用户的ID和向量
    sk_id = list()
    for i in range(j):
        sk_id.append(crypto.key_gen(ID_set[i], vector_y[i]))

    # 解密，随机一个用户
    index = random.randint(0, len(ID_set) - 1)
    decrypted_inner_product = Crypto_decrypt(crypto.mpk, ciphertext, ID_set, sk_id[index], vector_y[index])

if __name__ == '__main__':
    # 初始化系统     应该确保向量长度n大于等于S的大小
    total_begin_time = time.time()
    crypto = CryptoSystem(1, 200)

    # 用户数量
    maxnum = 1
    # 每种情况运算次数
    batch_size = 1000
    user_num = []
    elapsed_time = []

    # for j in range(1, maxnum + 1):
    #     print(f"--- 当前用户数量: {j} ---")
    #     user_num.append(j)
    #
    #     current_time = []
    #     for batch in range(1, batch_size + 1):
    #         print(f"用户数量: {j}, 第 {batch} 次计算")
    #
    #         start_time = time.time()
    #         EfficiencyTest(j)
    #         end_time = time.time()
    #         current_time.append(end_time - start_time)
    #
    #     sum_time = sum(current_time)
    #     elapsed_time.append(sum_time / batch_size)
    #
    # pprint(elapsed_time)
    for j in range(1, maxnum + 1):
        print(f"--- 当前用户数量: {j} ---")

        for batch in range(1, batch_size + 1):
            print(f"用户数量: {j}, 第 {batch} 次计算")
            user_num.append(batch)

            start_time = time.time()
            EfficiencyTest(j)
            end_time = time.time()
            current_time = end_time - start_time

            elapsed_time.append(current_time)

    pprint(elapsed_time)
    # 绘制柱状图
    plt.figure(figsize=(8, 6))
    plt.bar(user_num, elapsed_time, color='skyblue')
    plt.xlabel('Number of batches')
    plt.ylabel('Decryption time(s)')
    plt.title('Efficiency')
    plt.show()

    total_end_time = time.time()
    total_time = total_end_time - total_begin_time
    print(total_time)