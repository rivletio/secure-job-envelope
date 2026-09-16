import { Link, useRouterState } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { RivletMark } from "@/components/mark";
import { Button } from "@/components/ui/button";
import { SHOPS } from "@/lib/traveler/network";
import { useTravelerStore, type Role } from "@/lib/traveler/store";
import { cn } from "@/lib/utils";

export function AppShell({ children }: { children: ReactNode }) {
  const role = useTravelerStore((s) => s.role);
  const setRole = useTravelerStore((s) => s.setRole);
  const sellerOrgId = useTravelerStore((s) => s.sellerOrgId);
  const setSellerOrgId = useTravelerStore((s) => s.setSellerOrgId);
  const path = useRouterState({ select: (s) => s.location.pathname });

  return (
    <div className="paper-grid relative min-h-dvh text-foreground">
      <a href="#main" className="skip-link">
        Skip to desk
      </a>
      <header className="sticky top-0 z-40 border-b border-border bg-bg-deep">
        <div className="relative z-10 mx-auto flex max-w-6xl flex-wrap items-center gap-3 px-4 py-3">
          <Link to="/" className="group flex items-center gap-2.5">
            <RivletMark className="transition-transform duration-500 ease-[cubic-bezier(0.2,0.7,0.2,1)] group-hover:rotate-90" />
            <span className="leading-tight">
              <span className="block font-sans text-lg font-semibold tracking-tight text-paper">
                rivlet<span className="text-accent">.io</span>
              </span>
              <span className="block font-mono text-xs tracking-widest text-faint uppercase">
                Traveler 0.0.1
              </span>
            </span>
          </Link>
          <nav className="ml-auto flex flex-wrap items-center gap-1" aria-label="Primary">
            <NavLink to="/" active={path === "/"}>
              Desk
            </NavLink>
            <NavLink to="/new" active={path === "/new"}>
              New traveler
            </NavLink>
            <NavLink to="/spec" active={path === "/spec"}>
              Spec
            </NavLink>
            <NavLink to="/trust" active={path === "/trust"}>
              Trust
            </NavLink>
          </nav>
        </div>
        <div className="relative z-10 border-t border-border bg-bg">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-3 px-4 py-2">
            <RoleSwitch role={role} onChange={setRole} />
            {role === "seller" && (
              <label className="flex min-w-0 flex-1 items-center gap-2 font-mono text-xs tracking-wide text-soft uppercase">
                Quoting as
                <select
                  value={sellerOrgId}
                  onChange={(e) => setSellerOrgId(e.target.value)}
                  className="h-9 max-w-full flex-1 rounded-sm border border-border bg-card-navy px-2 font-sans text-sm font-medium tracking-normal text-text normal-case"
                >
                  {SHOPS.map((s) => (
                    <option key={s.org_id} value={s.org_id}>
                      {s.name} · {s.city}, {s.region}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {role === "buyer" && (
              <p className="font-mono text-xs tracking-wide text-faint uppercase">
                Buyer view — compose, award, export. Not identity.
              </p>
            )}
          </div>
        </div>
        <p className="border-t border-border bg-bg-deep px-4 py-1.5 text-center font-mono text-xs text-faint">
          Local desk · not a CUI system · role is a view, not authentication ·{" "}
          <Link to="/trust" className="text-soft underline-offset-2 hover:text-accent hover:underline">
            Trust
          </Link>
        </p>
      </header>
      <main id="main" className="relative z-10 mx-auto w-full max-w-6xl px-4 py-8 pb-16">
        {children}
      </main>
    </div>
  );
}

function NavLink({
  to,
  active,
  children,
}: {
  to: "/" | "/new" | "/spec" | "/trust";
  active: boolean;
  children: ReactNode;
}) {
  return (
    <Link
      to={to}
      aria-current={active ? "page" : undefined}
      className={cn(
        "rounded-sm px-3 py-2 font-mono text-xs font-medium tracking-widest uppercase focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        active ? "bg-accent/15 text-paper" : "text-soft hover:text-accent",
      )}
    >
      {children}
    </Link>
  );
}

function RoleSwitch({ role, onChange }: { role: Role; onChange: (r: Role) => void }) {
  return (
    <div
      className="inline-flex rounded-sm border border-border bg-card-navy p-0.5"
      role="radiogroup"
      aria-label="Demo role, not identity"
    >
      {(["buyer", "seller"] as const).map((r) => (
        <Button
          key={r}
          type="button"
          size="sm"
          role="radio"
          aria-checked={role === r}
          variant={role === r ? "default" : "ghost"}
          className="h-8 min-w-20 font-mono text-xs tracking-widest uppercase"
          onClick={() => onChange(r)}
        >
          {r === "buyer" ? "Buyer" : "Seller"}
        </Button>
      ))}
    </div>
  );
}
