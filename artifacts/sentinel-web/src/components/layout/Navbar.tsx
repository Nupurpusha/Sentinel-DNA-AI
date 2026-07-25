import { Link, useLocation } from "wouter";
import { Shield, Activity, Users, BarChart2, MonitorCheck } from "lucide-react";
import { cn } from "@/lib/utils";

export function Navbar() {
  const [location] = useLocation();

  return (
    <nav className="sticky top-0 z-50 w-full border-b border-border/50 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-14 items-center px-4 md:px-8">
        <div className="flex items-center gap-2 mr-6 text-primary">
          <Shield className="h-5 w-5" />
          <span className="font-semibold tracking-tight text-lg text-foreground">
            Sentinel<span className="text-primary">DNA</span>
          </span>
        </div>

        <div className="flex items-center space-x-1 text-sm font-medium overflow-x-auto">
          <NavLink href="/" active={location === "/"} icon={<Activity className="h-4 w-4" />} label="Data Foundation" testId="link-data-foundation" />
          <NavLink href="/identity" active={location.startsWith("/identity")} icon={<Users className="h-4 w-4" />} label="Identity Inspector" testId="link-identity-inspector" />
          <NavLink href="/soc" active={location.startsWith("/soc")} icon={<BarChart2 className="h-4 w-4" />} label="SOC Overview" testId="link-soc-overview" />
          <NavLink href="/model" active={location.startsWith("/model")} icon={<MonitorCheck className="h-4 w-4" />} label="Model Performance" testId="link-model-performance" />
        </div>
      </div>
    </nav>
  );
}

function NavLink({
  href, active, icon, label, testId,
}: { href: string; active: boolean; icon: React.ReactNode; label: string; testId?: string }) {
  return (
    <Link
      href={href}
      className={cn(
        "transition-colors hover:text-primary flex items-center gap-1.5 px-3 py-1.5 rounded-md whitespace-nowrap",
        active ? "text-foreground bg-muted/40" : "text-foreground/60"
      )}
      data-testid={testId}
    >
      {icon}
      {label}
    </Link>
  );
}
