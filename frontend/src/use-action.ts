import { useRef, useState } from "react";
import { requestErrorText } from "./api";
import { useLocale } from "./i18n";

/** Shared pending and failure feedback for actions outside a form. */
export function useAction() {
  useLocale();
  const running = useRef(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<{ error: unknown }>();
  async function run(action: () => Promise<void>) {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    setFailure(undefined);
    try {
      await action();
    } catch (error) {
      setFailure({ error });
    } finally {
      running.current = false;
      setBusy(false);
    }
  }
  const error = failure ? requestErrorText(failure.error) : "";
  const clearError = () => setFailure(undefined);
  return { busy, error, run, clearError };
}
