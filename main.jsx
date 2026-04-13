import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import YNTKTS from "./app.jsx";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <YNTKTS />
  </StrictMode>
);
