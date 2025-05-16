import { build } from 'esbuild'
import { dirname } from 'path'
import { fileURLToPath } from 'url'

// 获取当前目录的 ESM 兼容方式
const __dirname = dirname(fileURLToPath(import.meta.url))

// 使用 esbuild 进行高级构建
await build({
	entryPoints: ['src/index.ts'],  // 入口文件
	bundle: true,                   // 打包所有依赖
	minify: true,                   // 压缩代码
	outfile: 'dist/index.min.js',   // 输出文件路径
	platform: 'node',               // 目标平台
	target: 'node20',               // Node.js 20+ 环境
	format: 'esm',                  // 输出格式为 ESM
	sourcesContent: false           // 不包含源码内容
})
