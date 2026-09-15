import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./styles/theme.css";

// Theme is applied before first paint to avoid a flash of the wrong one.
const stored = localStorage.getItem("xox-theme");
const dark =
  stored === "dark" ||
  (stored === null && window.matchMedia("(prefers-color-scheme: dark)").matches);
if (dark) document.documentElement.classList.add("dark");

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
);
