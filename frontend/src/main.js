// main.js
import { createApp } from 'vue'
import App from './App.vue'

// ✅ 引入 Element Plus 主库和样式
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'

// ✅ 引入图标组件库
import * as ElementPlusIconsVue from '@element-plus/icons-vue'

const app = createApp(App)

// 注册组件库
app.use(ElementPlus)

// 注册全部图标
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component)
}

app.mount('#app')
