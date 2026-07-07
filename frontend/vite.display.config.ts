import { defineConfig, loadEnv } from 'vite'

export default defineConfig(({ mode }) => {
  const env = {
    ...loadEnv(mode, process.cwd(), ''),
    ...process.env,
  }

  const proxyTarget = env.VITE_API_PROXY_TARGET || 'http://127.0.0.1:8000'
  const displayPort = Number(env.VITE_DISPLAY_PORT || 5188)

  return {
    root: 'display',
    publicDir: '../public',
    server: {
      host: true,
      port: displayPort,
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
      port: Number(env.VITE_DISPLAY_PREVIEW_PORT || 4188),
      strictPort: false,
    },
  }
})
