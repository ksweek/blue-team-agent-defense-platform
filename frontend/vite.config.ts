import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig(({ mode }) => {
  const env = {
    ...loadEnv(mode, process.cwd(), ''),
    ...process.env,
  }
  const devPort = Number(env.VITE_PORT || 5173)
  const previewPort = Number(env.VITE_PREVIEW_PORT || 4173)
  const proxyTarget = env.VITE_API_PROXY_TARGET || 'http://127.0.0.1:8000'
  const publicBase = env.VITE_PUBLIC_BASE || '/'

  return {
    base: publicBase,
    plugins: [vue()],
    server: {
      host: true,
      port: devPort,
      strictPort: false,
      cors: true,
      allowedHosts: true,
      proxy: {
        '/api': {
          target: proxyTarget,
          changeOrigin: true,
          secure: false,
        },
      },
    },
    preview: {
      host: true,
      port: previewPort,
      strictPort: false,
    },
  }
})
