import random
from Utils import is_sent_finish, kl

import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, GPT2LMHeadModel
from Huffman import HuffmanCoding

tokenizer = AutoTokenizer.from_pretrained("gpt2")
model = GPT2LMHeadModel.from_pretrained("gpt2")

# try:
#     # 尝试读取用户输入的秘密消息
#     with open('temp_secret_message.txt', 'r') as f:
#         msg_str = f.read().strip()
# except FileNotFoundError:
#     # 如果文件不存在，随机生成秘密消息
#     def generate_random_bit_string(length):
#         bit_string = ""
#         for _ in range(length):
#             bit = random.choice(["0", "1"])
#             bit_string += bit
#         return bit_string
#
#     msg_len = 16
#     msg_str = generate_random_bit_string(msg_len)

msg_str = '1001110110101101'

# print('Your message string is: ', end='')   # 1001110110101101
# print(msg_str)
message = [int(char) for char in msg_str]

# 全局参数
bits_per_word = 3
prompt = "I'm a graduate student"   # 隐写文本前缀
context_str = prompt

# 函数内
output_str = context_str

# 测试指标
total_num = 0
total_num_for_stats = 0
total_log_probs = 0
total_kl = 0  # in bits
total_num_sents = 0

# print("The secret message is being steganographed...")

with torch.no_grad():
    i = 0
    sent_finish = False
    while i < len(message) or not sent_finish:
        output = tokenizer(output_str, return_tensors="pt")
        preds = model(**output, labels=output["input_ids"])
        logits = preds.logits
        logits[0, -1, -1] = -1e20
        logits[0, -1, 198] = -1e20
        logits[0, -1, 628] = -1e20
        logits, indices = logits[0, -1, :].sort(descending=True)

        # 得到2**bits的候选池
        indices = indices[:2 ** bits_per_word]
        log_probs = F.log_softmax(logits, dim=-1)[:2 ** bits_per_word]
        probs = torch.exp(log_probs)

        if i >= len(message):
            selection = 0
            sent_finish = is_sent_finish(indices[selection].item(), tokenizer)
        else:
            probs_array = probs.detach().numpy()
            coding = HuffmanCoding()
            coding.make_heap_from_array(probs_array)
            coding.merge_nodes()
            root = coding.make_codes()

            while root.token is None:
                if i >= len(message) or message[i] == 0:
                    root = root.left
                else:
                    root = root.right
                i += 1
            selection = root.token

            # 测试数据
            logq = torch.tensor([-len(coding.codes[idx]) for idx in range(len(probs_array))], dtype=torch.float)
            logq = logq * 0.69315
            q = torch.exp(logq)

            total_kl += kl(q, logq, log_probs)
            total_log_probs += log_probs[selection].item()
            total_num_for_stats += 1

        output_str_add = tokenizer.decode(indices[selection].view(1))
        output_str += output_str_add

        # print(output_str_add, end=(4 - len(output_str_add) // 4) * '\t')
        # print(str(i) + "\tbit(s) of message hiden.")

        total_num += 1

avg_NLL = -total_log_probs / total_num_for_stats
avg_KL = total_kl / total_num_for_stats
words_per_bit = total_num_for_stats / i
# print(total_num_for_stats)

text = output_str
print('Your steganographic text is \"' + text + "\"")
# with open(r"D:\project\Oniverse\file_pre_to_send\client1\stega.txt", 'w', encoding='utf-8') as file:
#     file.write(text)

# print("It has been saved to \"file_pre_to_send\".")

# print('Generated text: ' + text)
# print(avg_KL)
# print(avg_NLL)
# print(1 / words_per_bit)
# print('Decoding...')
#
# text = text[len(context_str):]
# print(text)
