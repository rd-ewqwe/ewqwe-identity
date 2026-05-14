/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,js}"],
  theme: {
    extend: {
      colors: {
        brand: {
          bg: "#181f38",
          mid: "#1f2745",
          indigo: "#7358cf",
          violet: "#9b7de8",
        },
      },
      backdropBlur: { lg: "16px" },
    },
  },
  plugins: [],
};
