import { useEffect, useState } from "react";
import { STORAGE_WRITE_FAILED, lastStorageWriteFailed } from "@/lib/traveler/store";

/** A standing warning while the browser is refusing to save the desk's state.
 *
 *  The desk keeps everything in browser storage, and a write there can fail — the quota
 *  is full, or storage is blocked. That failure used to be swallowed: the page went on
 *  looking saved, and the next reload threw the work away. It stays visible until a
 *  write goes through again. */
export function StorageWarning() {
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    setFailed(lastStorageWriteFailed());
    const onFail = () => setFailed(true);
    // Re-check after any interaction: the flag clears as soon as a write succeeds.
    const recheck = () => setFailed(lastStorageWriteFailed());
    window.addEventListener(STORAGE_WRITE_FAILED, onFail);
    window.addEventListener("click", recheck);
    window.addEventListener("keyup", recheck);
    return () => {
      window.removeEventListener(STORAGE_WRITE_FAILED, onFail);
      window.removeEventListener("click", recheck);
      window.removeEventListener("keyup", recheck);
    };
  }, []);
  if (!failed) return null;
  return (
    <p
      role="alert"
      className="border-t border-danger/40 bg-danger/15 px-4 py-2 text-center text-sm text-danger"
    >
      This browser is not saving your changes (its storage is full or blocked). What you see is
      only in this tab: export anything you need before you close or reload it.
    </p>
  );
}
