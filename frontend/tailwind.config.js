/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          900: '#0a0f1c', // Dark navy background
          800: '#111827',
          700: '#1f2937',
        },
        primary: {
          DEFAULT: '#3b82f6',
          dark: '#2563eb',
        },
        accent: {
          DEFAULT: '#8b5cf6',
          dark: '#7c3aed',
        },
        background: '#0a0f1c',
        foreground: '#f8fafc',
        card: {
          DEFAULT: 'rgba(17, 24, 39, 0.7)',
          foreground: '#f8fafc',
        },
        border: 'rgba(255, 255, 255, 0.1)',
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        heading: ['"Space Grotesk"', 'sans-serif'],
      },
      borderRadius: {
        'xl': '20px',
        '2xl': '24px',
      },
      backgroundImage: {
        'glass-gradient': 'linear-gradient(to bottom right, rgba(255, 255, 255, 0.05), rgba(255, 255, 255, 0.01))',
      },
    },
  },
  plugins: [],
}
