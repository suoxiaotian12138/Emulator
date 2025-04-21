import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, GPT2LMHeadModel
from Huffman import HuffmanCoding

tokenizer = AutoTokenizer.from_pretrained("gpt2")
model = GPT2LMHeadModel.from_pretrained("gpt2")

# 参数
msg_len = 16
bits_per_word = 3
prompt = "I'm a graduate student"   # 隐写文本前缀
context_str = prompt


# print("Reading the steganographic text from \"file_received\"...")
with open(r'D:\project\Oniverse\file_received\client2\ST.txt', 'r', encoding='utf-8') as file:
    text = file.read()

text = text[len(context_str):]

# print("Extracting the secret message...")
inp = tokenizer.encode(text)
output_str = context_str
message_recstr = []

with torch.no_grad():
    i = 0
    while i < len(inp):
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

        # 确定选择的单词
        rank = (indices == inp[i]).nonzero().item()

        probs_array = probs.cpu().numpy()
        coding = HuffmanCoding()
        coding.make_heap_from_array(probs_array)
        coding.merge_nodes()
        coding.make_codes()

        tokens_t = map(int, coding.codes[rank])
        message_recstr.extend(tokens_t)

        # 更新已经处理的句子
        output_str_add = tokenizer.decode(indices[rank].view(1))
        output_str += output_str_add

        i += 1

# print("The extraction is complete. Your secret message is: ", end='')
for i in range(msg_len):
    print(message_recstr[i], end='')
# print()
