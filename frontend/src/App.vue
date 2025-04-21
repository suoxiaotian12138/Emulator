<template>
    <div class="flex h-screen bg-gray-50">
        <div class="w-1/2 bg-gray-100 flex flex-col h-screen">

          <!-- 上半部分：节点按钮区域 -->
          <div class="h-1/2 flex flex-col justify-start items-center py-4">
            <!-- 标题行 -->
            <div class="grid grid-cols-7 w-full text-center mb-4">
              <div v-for="(section, idx) in sections" :key="'title-' + idx">
                <h3 class="text-lg font-bold">{{ section.title }}</h3>
              </div>
            </div>

            <!-- 按钮行，根据最大按钮数均匀分布在垂直空间中 -->
            <div class="flex-1 grid grid-cols-7 w-full px-4">
              <div
                v-for="(section, idx) in sections"
                :key="'column-' + idx"
                class="flex flex-col items-center justify-evenly"
              >
                <div
                  v-for="(button, index) in filteredButtons(section.key)"
                  :key="section.key + '-' + index"
                  class="flex flex-col items-center"
                >
                  <el-button
                    :type="section.type"
                    :icon="section.icon"
                    circle
                    class="circle-button"
                    :title="button.name"
                  />
                  <p class="node-label">{{ button.name }}</p>
                </div>
              </div>
            </div>
          </div>

          <!-- 下半部分：展示框内容 -->
  <div class="h-1/2 border-t border-gray-300 p-6 overflow-auto">
    <div class="bg-white border rounded-md shadow-md p-6 h-full transition duration-300 ease-in-out hover:shadow-lg">
      <h2 class="text-xl font-bold text-gray-800 mb-2">网络监控概览</h2>
      <p class="text-gray-600 mb-1">系统日志：</p>
      <div class="border p-3 rounded-md bg-opacity-50 bg-gray-50 h-64 overflow-y-auto">
        <pre v-for="(line, idx) in monitorLines" :key="'log-' + idx">{{ line }}</pre>
      </div>
    </div>
  </div>
        </div>

        <div class="w-1/2 flex flex-col p-4 space-y-4">
            <div v-for="(filename, index) in filenames" :key="index"
                :class="`border p-4 rounded-md shadow-md transition duration-300 ease-in-out hover:shadow-xl ${getBoxBgColor(index)}`">
                <h2 class="font-bold text-xl mb-2 {{ getTitleTextColor(index) }}">{{ getTitles(index) }}</h2>
                <div v-if="index === 0">
                    <p class="text-gray-600 mb-1">{{ tips[index] }}</p>
                    <div class="border p-2 rounded-md overflow-y-auto bg-opacity-50 bg-white" style="height: 8em;">
                        <pre>{{ contents[index].join('\n').replace(/\r/g, '') }}</pre>
                    </div>
                </div>
                <div v-else-if="index === 1">
                    <p class="text-gray-600 mb-1">{{ tips[index] }}</p>
                    <div class="border p-2 rounded-md overflow-hidden bg-opacity-50 bg-white" style="height: 2.5em;">
                        {{ contents[index].join(' ').replace(/\r/g, '') }}
                    </div>
                </div>
                <div v-else-if="index === 2">
                    <p class="text-gray-600 mb-1">【待填写提示词】</p>
                    <div class="border p-2 rounded-md overflow-hidden bg-opacity-50 bg-white" style="height: 2.5em;">
                        {{ contents[index].length > 0? contents[index][0].replace(/\r/g, '') : '暂无内容' }}
                    </div>
                    <p class="text-gray-600 mb-1 mt-2">【待填写提示词】</p>
                    <div class="border p-2 rounded-md overflow-y-auto bg-opacity-50 bg-white" style="height: 8em;">
                        {{ contents[index].length > 1? contents[index].slice(1).join('\n').replace(/\r/g, '') : '暂无内容' }}
                    </div>
                </div>
                <div v-else-if="index === 3">
                    <p class="text-gray-600 mb-1">生成的隐写文本：</p>
                    <div class="border p-2 rounded-md overflow-y-auto bg-opacity-50 bg-white" style="height: 2.5em;">
                        {{ contents[index].length > 0? contents[index][0].replace(/\r/g, '') : '暂无内容' }}
                    </div>
                    <p class="text-gray-600 mb-1 mt-2">提取的秘密消息：</p>
                    <div class="border p-2 rounded-md overflow-hidden bg-opacity-50 bg-white" style="height: 2.5em;">
                        {{ contents[index].length > 1? contents[index][1].replace(/\r/g, '') : '暂无内容' }}
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue';
import { User, Connection, Cpu } from '@element-plus/icons-vue'

const filenames = ['WC1.txt', 'WC2.txt', 'LHZ.txt', 'PFQ.txt'];
const tips = ['流量预测结果：', '恶意节点有：', '输出为：', '输出为：'];
const contents = ref(Array(4).fill([]));

const getBoxBgColor = (index) => {
    const colors = ['bg-blue-300', 'bg-green-300', 'bg-yellow-300', 'bg-purple-300'];
    return colors[index];
};

const monitorLines = ref([]);
let monitorIntervalId;

const readMonitorFile = async () => {
  try {
    const response = await fetch('/monitor.txt');  // 注意前面有 `/`，指向 public 根目录
    if (!response.ok) throw new Error('文件读取失败');
    const text = await response.text();
    monitorLines.value = text.split('\n').filter(line => line.trim() !== '');
  } catch (err) {
    console.error('读取 monitor.txt 出错:', err);
  }
};

const getTitleTextColor = (index) => {
    const colors = ['text-blue-700', 'text-green-700', 'text-yellow-700', 'text-purple-700'];
    return colors[index];
};

const getTitles = (index) => {
    const titles = ['加密流量识别', '恶意节点发现', '隐蔽信道', '文本隐写', '网络监控'];
    return titles[index];
};

const readFile = async (filename) => {
    try {
        const response = await fetch(filename);
        if (!response.ok) {
            throw new Error(`文件 ${filename} 读取失败`);
        }
        const text = await response.text();
        return text.split('\n').filter(line => line.trim()!== '');
    } catch (error) {
        console.error(error);
        return [];
    }
};

const updateFilesContent = async () => {
    for (let i = 0; i < filenames.length; i++) {
        contents.value[i] = await readFile(filenames[i]);
    }
};

let intervalId;

onMounted(async () => {
    await updateFilesContent();
    await readMonitorFile();
    await readButtonsFromFile('client_left', 'client.txt');
    await readButtonsFromFile('provider_left', 'provider.txt');
    await readButtonsFromFile('mix1', 'mix1.txt');
    await readButtonsFromFile('mix2', 'mix2.txt');
    await readButtonsFromFile('mix3', 'mix4.txt');
    await readButtonsFromFile('provider_right', 'provider.txt');
    await readButtonsFromFile('client_right', 'client.txt');

    intervalId = setInterval(updateFilesContent, 10000);
    monitorIntervalId = setInterval(readMonitorFile, 10000);
});

onUnmounted(() => {
    clearInterval(intervalId);
    clearInterval(monitorIntervalId);
});

const sections = [
  { title: 'Client', key: 'client_left', type: 'primary', icon: User },
  { title: 'Provider', key: 'provider_left', type: 'warning', icon: Cpu },
  { title: 'Mixnode', key: 'mix1', type: 'danger', icon: Connection },
  { title: 'Mixnode', key: 'mix2', type: 'danger', icon: Connection },
  { title: 'Mixnode', key: 'mix3', type: 'danger', icon: Connection },
  { title: 'Provider', key: 'provider_right', type: 'warning', icon: Cpu },
  { title: 'Client', key: 'client_right', type: 'primary', icon: User }
];

const buttons = ref({
  client_left: [],
  provider_left: [],
  mix1: [],
  mix2: [],
  mix3: [],
  provider_right: [],
  client_right: []
});

const readButtonsFromFile = async (type, filename) => {
  try {
    const response = await fetch(filename);
    if (!response.ok) throw new Error(`读取 ${filename} 失败`);
    const text = await response.text();
    const lines = text.split('\n').map(line => line.trim()).filter(Boolean);

    buttons.value[type] = lines.map(name => ({ name }));
  } catch (error) {
    console.error(error);
  }
};

const filteredButtons = (type) => {
  return buttons.value[type] || []
}
</script>

<style scoped>
/* 可以在这里添加自定义样式 */

.button-grid {
  position: relative;
  min-height: 300px;
}

.icon-button {
  width: 100px;
  height: 40px;
  text-align: center;
  z-index: 10;
}

.button-text {
  font-size: 14px;
  pointer-events: none; /* 保证拖动流畅 */
}

.circle-button {
  width: 64px;
  height: 64px;
  min-width: 64px;         /* 修复 el-button 内部强制 min-width 导致非正圆 */
  border-radius: 50%;
  font-size: 28px;
  padding: 0;
  line-height: 64px;        /* 保证文字或图标垂直居中 */
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.15);
}

.node-label {
  font-size: 14px;
  color: #333;
  text-align: center;
  margin-top: 8px;
}
</style>