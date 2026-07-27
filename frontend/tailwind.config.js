/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"Fira Code"', '"Space Mono"', 'monospace'],
      },
      colors: {
        // We will define CSS variables for dynamic themes
        term: {
          bg: 'var(--bg-color)',
          fg: 'var(--text-color)',
          border: 'var(--border-color)',
          accent: 'var(--accent-color)',
          dim: 'var(--dim-color)',
          warn: 'var(--warn-color)',
          error: 'var(--error-color)',
        }
      }
    },
  },
  plugins: [],
}
