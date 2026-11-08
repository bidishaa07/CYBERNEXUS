import type { Config } from 'tailwindcss';
export default { content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'], theme: { extend: { colors: { ink:'#070b14', panel:'#0e1523', line:'#233149', cyan:'#5eead4', blue:'#7dd3fc', amber:'#fbbf24', danger:'#fb7185' } } }, plugins: [] } satisfies Config;
