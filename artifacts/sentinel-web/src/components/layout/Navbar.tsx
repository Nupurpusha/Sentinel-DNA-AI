import { Link, useLocation } from "wouter";
import { Shield, Activity, Users } from "lucide-react";
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
        
        <div className="flex items-center space-x-6 text-sm font-medium">
          <Link 
            href="/" 
            className={cn(
              "transition-colors hover:text-primary flex items-center gap-2",
              location === "/" ? "text-foreground" : "text-foreground/60"
            )}
            data-testid="link-data-foundation"
          >
            <Activity className="h-4 w-4" />
            Data Foundation
          </Link>
          <Link 
            href="/identity" 
            className={cn(
              "transition-colors hover:text-primary flex items-center gap-2",
              location.startsWith("/identity") ? "text-foreground" : "text-foreground/60"
            )}
            data-testid="link-identity-inspector"
          >
            <Users className="h-4 w-4" />
            Identity Inspector
          </Link>
        </div>
      </div>
    </nav>
  );
}
