/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './templates/**/*.html',
    './src/**/*.rs',
  ],
  theme: {
    extend: {
      colors: {
        vouch: {
          bg: '#0a0a0a',
          surface: '#141414',
          raised: '#1e1e1e',
          border: '#2a2a2a',
          subtle: '#333333',
          accent: '#3ecf8e',
          'accent-hover': '#5edba5',
          success: '#2ea043',
          'success-bg': '#0d2818',
          error: '#d73a49',
          'error-bg': '#2d1214',
          warning: '#d29922',
          'warning-bg': '#2d2208',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'SF Mono', 'Monaco', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
