import { useEffect, type ReactNode } from "react";
import { TRAVELER_STORE_KEY, useTravelerStore } from "@/lib/traveler/store";
import { useKeysStore } from "@/lib/traveler/keys-store";

export function TravelerProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    void Promise.resolve(useTravelerStore.persist.rehydrate()).finally(() => {
      useTravelerStore.getState().setHydrated(true);
    });
    void Promise.resolve(useKeysStore.persist.rehydrate()).finally(() => {
      useKeysStore.getState().setHydrated(true);
    });
    // Another tab of this desk writes the same storage. Each tab persists its WHOLE
    // in-memory list, so a tab that never reloads would otherwise overwrite newer work
    // from stale state (a second tab's role toggle reverted an award made in the first).
    // Re-read whenever another tab writes, so this tab's next write starts from it.
    const onStorage = (e: StorageEvent) => {
      if (e.key === TRAVELER_STORE_KEY) void useTravelerStore.persist.rehydrate();
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);
  return children;
}
