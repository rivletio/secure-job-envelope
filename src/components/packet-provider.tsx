import { useEffect, type ReactNode } from "react";
import { usePacketStore } from "@/lib/packet/store";

export function PacketProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    void Promise.resolve(usePacketStore.persist.rehydrate()).then(() => {
      usePacketStore.getState().setHydrated(true);
    });
  }, []);
  return children;
}
