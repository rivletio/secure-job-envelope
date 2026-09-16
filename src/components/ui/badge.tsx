import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-sm border px-2 py-0.5 font-mono text-xs font-medium tracking-wide",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        outline: "border-border text-foreground",
        mill: "border-accent/40 bg-accent/10 text-accent",
        paper: "border-line bg-wash text-muted-foreground",
        warn: "border-warn/30 bg-warn/10 text-warn",
      },
    },
    defaultVariants: { variant: "outline" },
  },
);

export function Badge({
  className,
  variant,
  ...props
}: HTMLAttributes<HTMLDivElement> & VariantProps<typeof badgeVariants>) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}
