import { useEffect, type ReactNode } from "react";
import { useTravelerStore } from "@/lib/traveler/store";

export function TravelerProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    void Promise.resolve(useTravelerStore.persist.rehydrate()).then(() => {
      useTravelerStore.getState().setHydrated(true);
    });
  }, []);
  return children;
}
