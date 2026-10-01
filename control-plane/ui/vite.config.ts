/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const devPort = Number(process.env.WEB_CONSOLE_PORT) || 18300
const apiTarget = process.env.VITE_API_PROXY || 'http://localhost:18081'

export default defineConfig({
  plugins: [react()],
  server: {
    port: devPort,
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    globals: true,
  },
})
