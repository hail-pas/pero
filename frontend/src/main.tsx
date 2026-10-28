import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { App, InitialLoading, pageLoader } from "./app";
import { LocaleProvider } from "./i18n";
import "./styles.css";
import { ThemeProvider } from "./theme";
const router = createBrowserRouter([
  {
    path: "*",
    loader: pageLoader,
    element: <App />,
    hydrateFallbackElement: <InitialLoading />,
  },
]);
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <LocaleProvider>
      <ThemeProvider>
        <RouterProvider router={router} />
      </ThemeProvider>
    </LocaleProvider>
  </React.StrictMode>,
);
