import { defineConfig, loadEnv } from 'vite'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig(({mode})=>{
  const env=loadEnv(mode,process.cwd(),'VITE_')
  const target=env.VITE_API_PROXY_TARGET||'http://192.168.56.1:8000'
  return {plugins:[tailwindcss()],server:{host:'127.0.0.1',port:5173,proxy:{'/api':{target,changeOrigin:true}}}}
})
