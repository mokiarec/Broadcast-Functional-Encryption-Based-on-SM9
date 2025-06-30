from pprint import pprint
from tkinter import *
from tkinter import simpledialog, messagebox

from numpy import broadcast

from CryptoSystem import CryptoSystem, Crypto_decrypt, Crypto_encrypt
from pypbc import Element, Zr

# 用户ID集
S = list()
# 用户向量集
y = list()
# 密文
CT = dict()
# 明文
result = int()

class User:
    def __init__(self, crypto: CryptoSystem, ID: str):
        self.crypto = crypto
        self.ID = ID
        self.y_j = crypto.generate_y()
        self.SK = {}

    def generate_SK(self, sk1_label: Label, sk2_label: Label):
        self.SK = self.crypto.key_gen(self.ID, self.y_j)
        print(f"用户 {self.ID} 的 SK: {self.SK}")
        sk1_label.config(text=f"私钥中的K1: {self.SK['K1']}")
        sk2_label.config(text=f"私钥中的K2: {self.SK['K2']}")

    def encrypt(self, vector_x: list, S: list):
        global CT
        print(f"用户 {self.ID} 加密前的明文: {vector_x}")
        CT = Crypto_encrypt(vector_x, self.crypto.mpk, S)
        print(f"用户 {self.ID} 加密后的密文: {CT}")

    def decrypt(self, CT: dict, S: list, plaintext: Text):
        global result
        result = Crypto_decrypt(self.crypto.mpk, CT, S, self.SK, self.y_j)
        plaintext.insert(1.0, str(result))
        print(f"用户 {self.ID} 解密后的明文: {result}")

class ChatDialog:
    def __init__(self, root):
        self.root = root
        self.root.title("加密系统")

        # 创建一个文本框用于显示对话历史
        self.text_area = Text(self.root)
        self.text_area.pack(fill=BOTH, expand=True, pady=5)  # 让 Text 控件填充整个窗口并随窗口大小变化
        # 配置行和列的权重，以便它们在窗口大小变化时能够扩展
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(0, weight=1)
        self.text_area.config(state='disabled')  # 禁止用户编辑

    def display_message(self, message: str):
        self.text_area.config(state='normal')  # 允许编辑
        self.text_area.insert(END, message + "\n\n")
        self.text_area.config(state='disabled')  # 禁止编辑
        self.text_area.see(END)  # 滚动到最新消息

def display_mpk(chat_dialog: ChatDialog, crypto: CryptoSystem):
    chat_dialog.display_message("System: " + str(crypto.mpk))

def broadcast_CT(chat_dialog: ChatDialog, CT: dict):
    chat_dialog.display_message("System: " + str(CT))
    print(f"广播的密文: {CT}")

def open_user_window(chat_dialog: ChatDialog):
    # 弹出输入框，要求用户输入ID
    user_id = simpledialog.askstring("输入ID", "请输入您的ID：", parent=root)

    global CT, S, y

    if user_id:  # 如果用户输入了ID
        user = User(crypto, user_id)

        user.ID = user_id
        S.append(user_id)
        y.append(user.y_j)
        chat_dialog.display_message("System: " + str(f"用户 {user.ID} 加入！"))
        print(f"用户 {user.ID} 加入！")
        pprint(f"当前的S: {S}")
        pprint(f"当前的y: {y}")

        # 创建子窗口
        user_window = Toplevel(root)
        user_window.protocol("WM_DELETE_WINDOW", lambda :close_user_window(user, user_window, chat_dialog))
        user_window.title(f"用户 {user.ID}")
        user_window.geometry("300x500")  # 设置子窗口的大小

        # 在子窗口中添加一个标签，显示用户输入的ID
        id_label = Label(user_window, text=f"欢迎，您的ID是: {user_id}")
        id_label.pack(pady=20)

        # K1标签
        sk_k1_label = Label(user_window, text=f"私钥中的K1: ", anchor=W)
        sk_k1_label.pack(pady=5)

        # K2标签
        sk_k2_label = Label(user_window, text=f"私钥中的K2: ", anchor=W)
        sk_k2_label.pack(pady=5)

        # 获取用户私钥按钮
        sk_button = Button(user_window, text="获取用户私钥", command=lambda :user.generate_SK(sk_k1_label, sk_k2_label))
        sk_button.pack(pady=10)

        # 创建一个 input_frame 作为容器
        input_frame = Frame(user_window)
        input_frame.pack(fill=X, padx=5, pady=5)

        # 创建一个 output_frame 作为容器
        output_frame = Frame(user_window)
        output_frame.pack(fill=X, padx=5, pady=5)  # 使用 pack 将 Frame 添加到父容器

        # 输入加密的明文
        encrypt_label = Label(input_frame, text=f"输入明文：")
        encrypt_label.pack(side=LEFT, fill=X, padx=5, pady=5)
        cipher_entry = Entry(input_frame)
        cipher_entry.pack(side=RIGHT, fill=X, expand=True, padx=5, pady=5)

        # 解密结果标签
        decrypt_label = Label(output_frame, text=f"解密结果：")
        decrypt_label.pack(side=LEFT, fill=X, padx=5, pady=5)
        plaintext = Text(output_frame, height=5, width=40, state="normal", wrap=WORD)
        plaintext.pack(side=RIGHT, fill=X, expand=True, padx=5, pady=5)

        # 创建一个 button_frame 作为容器
        button_frame = Frame(user_window)
        button_frame.pack(fill=BOTH, padx=5, pady=5)

        # 纵1
        frame1 = Frame(button_frame)
        frame1.pack(fill=Y, padx=5, pady=5)

        # 加密
        vector_x = [Element.random(crypto.mpk['BG'], Zr) for _ in range(crypto.mpk['n'])]

        encrypt_button = Button(frame1, text="加密", command=lambda :user.encrypt(vector_x, S))
        encrypt_button.pack(side=LEFT, padx=5, pady=5)

        # 解密
        encrypt_button = Button(frame1, text="解密", command=lambda :user.decrypt(CT, S, plaintext))
        encrypt_button.pack(side=RIGHT, padx=5, pady=5)

        # 纵2
        frame2 = Frame(button_frame)
        frame2.pack(fill=Y, padx=5, pady=5)

        # 广播
        broadcast_button = Button(frame2, text="广播", command=lambda :broadcast_CT(chat_dialog, CT))
        broadcast_button.pack(side=LEFT, padx=5, pady=5)

        # 关闭
        close_button = Button(frame2, text="关闭", command=lambda :close_user_window(user, user_window))
        close_button.pack(side=RIGHT, padx=5, pady=5)

    else:
        # 如果用户取消输入或关闭输入框，弹出提示
        messagebox.showinfo("提示", "您未输入ID，子窗口未打开。")

def close_user_window(user: User, user_window: Toplevel, chat_dialog: ChatDialog):
    global S, y
    try:
        S.remove(user.ID)
        y.remove(user.y_j)
    except ValueError:
        print("值不在列表中")
    print(f"用户 {user.ID} 退出！")
    pprint(f"当前的S: {S}")
    pprint(f"当前的y: {y}")

    chat_dialog.display_message("System: " + str(f"用户 {user.ID} 退出！"))
    user_window.destroy()


if __name__ == '__main__':

    root = Tk()  # 创建窗口对象的背景色
    root.geometry("900x900")
    # 生成对话框
    app = ChatDialog(root)

    # 系统初始化
    crypto = CryptoSystem(1024, 64)
    app.display_message("System: " + "系统初始化成功！")
    # 打印加密系统的mpk
    display_mpk(app, crypto)

    # 页面布局
    param_frame = Frame(root)
    param_frame.pack(fill=X, padx=5, pady=5)

    BG_label = Label(param_frame, text=f"双线性对BG: {crypto.mpk['BG']}")
    BG_label.pack(side=TOP, fill=Y, padx=5, pady=5)
    g_label = Label(param_frame, text=f"群G1的生成元g: {crypto.mpk['g']}")
    g_label.pack(side=TOP, fill=Y, padx=5, pady=5)
    h_label = Label(param_frame, text=f"群G2的生成元h: {crypto.mpk['h']}")
    h_label.pack(side=TOP, fill=Y, padx=5, pady=5)
    g_gamma1_label = Label(param_frame, text=f"g^gamma1: {crypto.mpk['g_gamma1']}")
    g_gamma1_label.pack(side=TOP, fill=Y, padx=5, pady=5)
    g_eta1_alpha_alpha_label = Label(param_frame, text=f"g^(eta1*alpha*alpha): {crypto.mpk['g_eta1*alpha*alpha']}")
    g_eta1_alpha_alpha_label.pack(side=TOP, fill=Y, padx=5, pady=5)
    g_gamma2_eta2_alpha_label = Label(param_frame, text=f"g^(gamma2*eta2*alpha): {crypto.mpk['g_gamma2*eta2*alpha']}")
    g_gamma2_eta2_alpha_label.pack(side=TOP, fill=Y, padx=5, pady=5)
    h_gamma1_label = Label(param_frame, text=f"h^gamma1: {crypto.mpk['h_gamma1']}")
    h_gamma1_label.pack(side=TOP, fill=Y, padx=5, pady=5)

    user_manage_frame = Frame(root)
    user_manage_frame.pack(pady=10)

    user_generate_button = Button(user_manage_frame, text="新用户", command=lambda :open_user_window(app))
    user_generate_button.pack(pady=10)

    root.mainloop()  # 进入消息循环