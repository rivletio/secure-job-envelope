import { useEffect, type ReactNode } from "react";
import { useTravelerStore } from "@/lib/traveler/store";
import { useKeysStore } from "@/lib/traveler/keys-store";

export function TravelerProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    void Promise.resolve(useTravelerStore.persist.rehydrate()).finally(() => {
      useTravelerStore.getState().setHydrated(true);
    });
    void Promise.resolve(useKeysStore.persist.rehydrate()).finally(() => {
      useKeysStore.getState().setHydrated(true);
    });
  }, []);
  return children;
}
