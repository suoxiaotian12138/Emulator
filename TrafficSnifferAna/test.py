# test_model.py

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
import pandas as pd
import numpy as np
import json
from torch.utils.data import Dataset, DataLoader
from train import little_pets
from typing import List, Optional, Callable

# ------------------------------
# 模型定义部分（与你训练时保持一致）
# ------------------------------

num_time_steps = 16
input_size = 3
hidden_size = 16
output_size = 3
num_layers = 1
lr = 0.01

c_target = 128
chunk = 3
long = 256
w1 = int(long / 2) + 1
w2 = int(w1 / 2)
linear = 11904


# ------------------------------
# 数据集类
# ------------------------------

class DatasetFromCSV(Dataset):
    def __init__(self, csv_file):
        self.XandY = pd.read_csv(csv_file, header=None)
        self.labels = list(set(self.XandY.iloc[:, 1]))

    def __getitem__(self, idx):
        x = json.loads(self.XandY.iloc[idx, 0])
        x = np.array(x) / 255
        x = np.reshape(x, (chunk, long)).astype(np.float32)
        return torch.from_numpy(x), int(self.XandY.iloc[idx, 1])

    def __len__(self):
        return len(self.XandY)


# ------------------------------
# 推理入口
# ------------------------------

def evaluate_model():
    root_path = './dataset'  # 根据你的实际路径调整
    model_path = f'{root_path}/model.pth.tar'  # 修改为你的模型文件名
    test_csv = f'{root_path}/test_256.csv'

    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    test_dataset = DatasetFromCSV(test_csv)
    test_loader = DataLoader(test_dataset, batch_size=80, shuffle=False)
    print(len(test_dataset.labels))
    model = little_pets(num_classes=len(test_dataset.labels))
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.to(device)
    model.eval()

    correct = 0
    total = 0
    results = []

    with torch.no_grad():
        for batch_flows, batch_labels in test_loader:
            data, labels = batch_flows.to(device), batch_labels.to(device)
            outputs = model(data)
            predicted = torch.argmax(outputs, dim=1)
            correct += (predicted == labels).sum().item()
            total += labels.size(0)
            for pred, label in zip(predicted.cpu().numpy(), labels.cpu().numpy()):
                results.append({'predict': int(pred), 'label': int(label)})

    accuracy = correct / total
    print(f'Test Accuracy: {accuracy:.4f}')

    df = pd.DataFrame(results)
    df.to_csv(f'{root_path}/predict_results.csv', index=False)
    print(f'预测结果已保存到 {root_path}/predict_results.csv')


if __name__ == '__main__':
    evaluate_model()
