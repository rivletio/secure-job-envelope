import { createRootRoute, HeadContent, Outlet, Scripts } from "@tanstack/react-router";
import { TravelerProvider } from "@/components/traveler-provider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "sonner";
import appCss from "../styles.css?url";

const APP_NAME = "SJE";

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: APP_NAME },
      { name: "theme-color", content: "#0F2440" },
      {
        name: "description",
        content:
          "A SJE is a content-addressed job envelope for one part family moving between two US manufacturers.",
      },
    ],
    // Same-origin only. The fonts (Fraunces, Archivo, IBM Plex Mono) are self-hosted: their
    // @font-face rules live in styles.css and Vite bundles the files next to the app. No
    // third-party stylesheet may be linked here — this document is where the passphrase is
    // typed, and whoever serves a stylesheet can read attribute values with CSS selectors.
    // The published desk's Content-Security-Policy (scripts/pages-csp.mjs) allows nothing
    // but this origin, and the Pages build fails on a reference to any other.
    links: [
      // Under the app's base path, like every other asset: on Pages the desk is served from
      // a sub-path, and "/favicon.svg" would leave the site altogether.
      { rel: "icon", type: "image/svg+xml", href: `${import.meta.env.BASE_URL}favicon.svg` },
      { rel: "stylesheet", href: appCss },
    ],
  }),
  component: () => (
    <html lang="en" className="antialiased" suppressHydrationWarning>
      <head>
        <HeadContent />
      </head>
      <body>
        <TooltipProvider delayDuration={200}>
          <TravelerProvider>
            <Outlet />
          </TravelerProvider>
        </TooltipProvider>
        <Toaster position="bottom-center" richColors={false} />
        <Scripts />
      </body>
    </html>
  ),
});
