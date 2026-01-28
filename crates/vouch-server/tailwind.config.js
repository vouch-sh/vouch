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
          bg: '#0f1b2d',
          surface: '#1a2332',
          raised: '#243040',
          border: '#354150',
          subtle: '#2a3544',
          accent: '#539fe5',
          'accent-hover': '#89bceb',
          success: '#2ea043',
          'success-bg': '#0d2818',
          error: '#d73a49',
          'error-bg': '#2d1214',
          warning: '#d29922',
          'warning-bg': '#2d2208',
        },
      },
      fontFamily: {
        mono: ['SF Mono', 'Monaco', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
