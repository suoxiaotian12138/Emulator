# -*- coding: utf-8 -*-

import torch
import torch.nn as nn
import torch.nn
import torch.nn.functional as F
import pandas as pd
import os
from torch.nn import init
import time
from typing import Callable, List, Optional
from torch.utils.data.dataset import Dataset
from torch.utils.data.dataloader import DataLoader
import numpy as np
import pandas as pd
import json
import torch.nn.functional as F
import torch.nn as nn
import torch.optim as optim
import time

# 全局变量
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


class Conv1DLNActivation(nn.Sequential):
    def __init__(self,
                 in_channels: int,
                 out_channels: int,
                 kernel_size: int,
                 lnw: int,
                 stride: int = 1,
                 dilation: int = 1,
                 groups: int = 1,
                 norm_layer: Optional[Callable[..., nn.Module]] = None,
                 activation_layer: Optional[Callable[..., nn.Module]] = None,
                 padding=-1):

        if norm_layer is None:
            norm_layer = nn.LayerNorm
        if padding == -1:
            padding = 'same'
        super(Conv1DLNActivation, self).__init__()
        layers: List[nn.Module] = []
        layers.append(nn.Conv1d(in_channels=in_channels,
                                out_channels=out_channels,
                                kernel_size=(kernel_size,),
                                padding=padding,
                                stride=(stride,),
                                groups=groups,
                                dilation=(dilation,)
                                )),
        layers.append(norm_layer(lnw, eps=0.001)),
        if activation_layer is not None:
            layers.append(activation_layer(inplace=True))
        self.bw = nn.Sequential(*layers)

    def forward(self, x):
        x = self.bw(x)
        return x


class TestModel2(nn.Module):
    def __init__(self, size):
        super(TestModel2, self, ).__init__()
        layers: List[nn.Module] = []
        self.conv1_l = Conv1DLNActivation(1, 1, 2, w1, 2, 1, 1, None, nn.ReLU, padding=1)
        self.conv2_r = Conv1DLNActivation(1, 1, 3, w1, 2, 1, 1, None, nn.ReLU, padding=2)
        self.covtest = Conv1DLNActivation(1, 3, 3, w1, 1, 1, 1, None, nn.ReLU, padding=2)
        self.LN1 = nn.LayerNorm(size, eps=0.001)
        self.BN1 = nn.BatchNorm1d(3, eps=0.001, momentum=0.01)
        self.pool2_2 = nn.AvgPool1d(3, stride=2)
        self.adapool = nn.AdaptiveAvgPool1d(size)

        self.dw_1x1_up_3_16 = Conv1DLNActivation(int(3), int(c_target), 1, w2, 1, 1, 1, None, nn.ReLU)

        self.dw_1x1_up_conv2 = Conv1DLNActivation(int(3), int(3 * c_target), 1, w2, 1, 1, 1, None, nn.ReLU)
        self.dw_conv2 = Conv1DLNActivation(int(3 * c_target), int(3 * c_target), 2, w2, 1, 1, int(3 * c_target), None,
                                           nn.ReLU)
        self.dw_1x1_conv2 = nn.Conv1d(int(3 * c_target), int(c_target), (1,))

        self.LN2 = nn.LayerNorm(w2, eps=0.001)
        self.BN2 = nn.BatchNorm1d(16, eps=0.001, momentum=0.01)
        self.drop = nn.Dropout(p=0.1, inplace=True)

        self.adapool2 = nn.AdaptiveAvgPool1d(24)

        self.testSS1 = Conv1DLNActivation(3, c_target, 2, w2, 1, 1, 1, None, nn.ReLU)

    def forward(self, x):
        out_l = self.conv1_l(x)
        out_r = self.conv2_r(x)
        out_m = self.adapool(x)

        out = torch.cat((out_m, out_l, out_r), 1)

        out = self.LN1(out)
        out = self.pool2_2(out)
        out = self.drop(out)

        m = self.dw_1x1_up_3_16(out)

        out = self.dw_1x1_up_conv2(out)
        out = self.dw_conv2(out)
        out = self.dw_1x1_conv2(out)

        out = m + out

        out = self.LN2(out)
        out = self.pool2_2(out)
        out = self.drop(out)

        return out


class little_pets(nn.Module):
    def __init__(self, num_classes):
        super(little_pets, self).__init__()
        self.pet1 = TestModel2(w1)
        self.pet2 = TestModel2(w1)
        self.pet3 = TestModel2(w1)

        self.classifier = nn.Sequential(
            nn.Linear(linear, 64),
            nn.Hardswish(inplace=True),
            nn.Dropout(p=0.5, inplace=True),
            nn.Linear(64, num_classes))

    def forward(self, x):
        a = torch.chunk(x, chunk, 1)
        x1 = a[0]
        x2 = a[1]
        x3 = a[2]

        x1 = self.pet1(x1)
        x2 = self.pet2(x2)
        x3 = self.pet2(x3)

        out = torch.concat((x1, x2, x3), 1)

        out = torch.flatten(out, 1)

        out = self.classifier(out)
        return out


"""# **这是用来测试模型的可用性**"""

x = torch.randn(1, chunk, long)
model = little_pets(10)
out = model(x)
print(out.shape)


class DatasetFromCSV(Dataset):
    def __init__(self, csv_file):
        self.XandY = pd.read_csv(csv_file, header=None)
        self.labels = list(set(list(self.XandY.iloc[:, 1])))

    def __getitem__(self, id):
        return self.spiltXitem(self.XandY.iloc[id, 0]), int(self.XandY.iloc[id, 1])

    def __len__(self):
        return len(self.XandY)

    def label_to_ids(self, label):
        return

    def spiltXitem(self, xitem):
        x = json.loads(xitem)
        x = np.array(x) / 255
        # x = np.reshape(x, (1, 3, 500))
        x = np.reshape(x, (chunk, long)).astype(np.float32)
        return x
        # return x.astype(np.float32)


"""# **这是运行模型的**"""
if __name__ == '__main__':

    import os

    os.chdir("/content/drive/MyDrive/Colab Notebooks/")

    datasetname = 'dataset'
    name = datasetname + '_csv'
    root_path = '/content/drive/MyDrive/Colab Notebooks/' + name
    tag = 'C128_' + datasetname

    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    train_data = DatasetFromCSV(root_path + '/train_256.csv')
    test_data = DatasetFromCSV(root_path + '/test_256.csv')
    print('all label type ', len(train_data.labels))
    print(tag)
    net = little_pets(len(train_data.labels))
    net.to(device=device)
    max_acc = 0.95
    epoch_num = 300
    batch_size = 80
    optimizer = optim.Adam(net.parameters(), lr=0.001, weight_decay=1e-4)
    loss_function = nn.CrossEntropyLoss()
    train_loader = DataLoader(dataset=train_data, batch_size=batch_size, shuffle=True)
    train_steps = len(train_loader)

    test_loader = DataLoader(dataset=test_data, batch_size=batch_size, shuffle=False)
    for epoch in range(epoch_num):
        net.train()
        running_loss = 0.0
        all_time = 0
        step = 0
        for batch_flows, batch_labels in train_loader:
            step += 1
            data, labels = batch_flows, batch_labels
            optimizer.zero_grad()
            timeS = time.time()
            logits = net(data.to(device))
            loss = loss_function(logits, labels.to(device))
            loss.backward()
            optimizer.step()
            timeE = time.time()
            running_loss += loss.item()
            all_time += timeE - timeS
        net.eval()
        train_acc = 0.0
        acc = 0.0
        time_E = 0
        with torch.no_grad():
            for batch_flows, batch_labels in train_loader:
                data, labels = batch_flows, batch_labels
                outputs = net(data.to(device))
                # outputs = outputs.logits
                predict_y = torch.max(outputs, dim=1)[1]
                train_acc += torch.eq(predict_y, labels.to(device)).sum().item()
            for batch_flows, batch_labels in test_loader:
                data, labels = batch_flows, batch_labels
                timeS_E = time.time()
                outputs = net(data.to(device))
                # outputs = outputs.logits
                timeE_E = time.time()
                predict_y = torch.max(outputs, dim=1)[1]
                acc += torch.eq(predict_y, labels.to(device)).sum().item()
                time_E += timeE_E - timeS_E
            val_accurate = acc / len(test_data)
            train_accurate = train_acc / len(train_data)
            if (val_accurate > max_acc):
                max_acc = val_accurate
                torch.save(net.state_dict(),
                           root_path + '/' + tag + '-' + str(val_accurate) + '_' + str(time.time()) + '.pth.tar')
            print(
                '[epoch %d] train_loss: %.4f  train_accuracy: %.4f val_accuracy: %.4f epoch_time:  %.4f test_time:  %.4f' %
                (epoch + 1, running_loss / train_steps, train_accurate, val_accurate, all_time,
                 time_E * 1000 / len(test_data)))
