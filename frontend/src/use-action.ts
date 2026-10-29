import { useRef, useState } from "react";

/** Shared pending and failure feedback for actions outside a form. */
export function useAction() {
  const running = useRef(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function run(action: () => Promise<void>) {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (error) {
      setError((error as Error).message);
    } finally {
      running.current = false;
      setBusy(false);
    }
  }
  const clearError = () => setError("");
  return { busy, error, run, clearError };
}
