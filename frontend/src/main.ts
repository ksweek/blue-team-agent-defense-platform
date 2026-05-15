import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import './style.css'

document.title = '蓝队防御管理平台'

createApp(App).use(router).mount('#app')
