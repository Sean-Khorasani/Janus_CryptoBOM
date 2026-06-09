import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ['selector', '[data-theme="dark"]'],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"]
      },
      colors: {
        surface: "var(--color-surface)",
        border: "var(--color-border)",
        "text-primary": "var(--color-text-primary)",
        "text-muted": "var(--color-text-muted)",
        subtle: "var(--color-subtle)",
        hover: "var(--color-hover)",
        accent: "var(--color-accent)",
      },
      boxShadow: {
        card: "var(--shadow-sm)",
        "card-hover": "var(--shadow-md)",
        "card-lg": "var(--shadow-lg)",
      },
      borderRadius: {
        card: "var(--radius-md)",
      },
    }
  },
  plugins: []
} satisfies Config;

