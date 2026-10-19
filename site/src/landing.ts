import "./style.css";
import { registerSW } from "./ui.ts";

registerSW();

/** Progressive install affordance: the button stays hidden until the browser
 *  signals the demos are installable, and disappears again once installed. */
type InstallPrompt = Event & {
  prompt: () => void;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
};

let deferred: InstallPrompt | null = null;
const btn = document.querySelector<HTMLButtonElement>("#install");

window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault();
  deferred = e as InstallPrompt;
  if (btn) btn.hidden = false;
});

btn?.addEventListener("click", async () => {
  if (!deferred) return;
  deferred.prompt();
  await deferred.userChoice.catch(() => {});
  deferred = null;
  btn.hidden = true;
});

window.addEventListener("appinstalled", () => {
  if (btn) btn.hidden = true;
});
