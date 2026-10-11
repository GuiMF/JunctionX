import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Standalone `npm run dev` only. `vercel dev` routes /api to app itself.
    proxy: { '/api': 'http://127.0.0.1:8000' },
  },
});
