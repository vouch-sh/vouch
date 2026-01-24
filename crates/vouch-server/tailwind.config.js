/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './templates/**/*.html',
    './src/**/*.rs',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Vouch brand colors
        vouch: {
          50: '#f5f3ff',
          100: '#ede9fe',
          200: '#ddd6fe',
          300: '#c4b5fd',
          400: '#a78bfa',
          500: '#667eea',
          600: '#5a67d8',
          700: '#4c51bf',
          800: '#434190',
          900: '#3c366b',
        },
      },
      fontFamily: {
        mono: ['SF Mono', 'Monaco', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
