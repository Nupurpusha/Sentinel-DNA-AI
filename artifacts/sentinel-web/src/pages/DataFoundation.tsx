import { useState, useEffect } from "react";
import { Summary, EventsResponse, EventRow } from "@/types";
import { formatNumber, formatPercent, cn, formatDate } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { RefreshCw, Download, Search, CheckCircle2, XCircle, ShieldAlert } from "lucide-react";
import { Link } from "wouter";

export function DataFoundation() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loadingSummary, setLoadingSummary] = useState(true);
  const [regenerating, setRegenerating] = useState(false);

  const [events, setEvents] = useState<EventsResponse | null>(null);
  const [loadingEvents, setLoadingEvents] = useState(true);

  // Filters
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [entityType, setEntityType] = useState<string>("all");
  const [department, setDepartment] = useState<string>("all");
  const [label, setLabel] = useState<string>("all");

  const fetchSummary = async () => {
    setLoadingSummary(true);
    try {
      const res = await fetch("/sentinel-api/summary");
      if (res.ok) {
        setSummary(await res.json());
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingSummary(false);
    }
  };

  const fetchEvents = async () => {
    setLoadingEvents(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: "50",
      });
      if (search) params.append("search", search);
      if (entityType !== "all") params.append("entity_type", entityType);
      if (department !== "all") params.append("department", department);
      if (label !== "all") params.append("label", label);

      const res = await fetch(`/sentinel-api/events?${params.toString()}`);
      if (res.ok) {
        setEvents(await res.json());
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingEvents(false);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, []);

  useEffect(() => {
    fetchEvents();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, search, entityType, department, label]);

  const handleRegenerate = async () => {
    setRegenerating(true);
    try {
      await fetch("/sentinel-api/regenerate", { method: "POST" });
      await fetchSummary();
      setPage(1);
      await fetchEvents();
    } catch (err) {
      console.error(err);
    } finally {
      setRegenerating(false);
    }
  };

  const handleExport = () => {
    window.location.href = "/sentinel-api/export/csv";
  };

  const getLabelColor = (lbl: string) => {
    if (lbl === "normal") return "success";
    if (lbl.includes("drift") || lbl.includes("spoofing")) return "warning";
    return "destructive";
  };

  return (
    <div className="container py-8 px-4 md:px-8 max-w-7xl mx-auto space-y-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">Data Foundation</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            Inspect raw synthetic telemetry and behavioral data.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button 
            variant="outline" 
            onClick={handleExport}
            data-testid="button-export"
          >
            <Download className="mr-2 h-4 w-4" />
            Export CSV
          </Button>
          <Button 
            onClick={handleRegenerate} 
            disabled={regenerating}
            data-testid="button-regenerate"
          >
            <RefreshCw className={cn("mr-2 h-4 w-4", regenerating && "animate-spin")} />
            Regenerate Dataset
          </Button>
        </div>
      </div>

      {loadingSummary && !summary ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 animate-pulse">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 bg-muted/50 rounded-lg border border-border/50"></div>
          ))}
        </div>
      ) : summary ? (
        <div className="space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="py-4">
                <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground font-semibold">Total Events</CardTitle>
                <p className="text-3xl font-bold font-mono tracking-tight text-primary mt-2">
                  {formatNumber(summary.total_events)}
                </p>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="py-4">
                <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground font-semibold">Total Identities</CardTitle>
                <p className="text-3xl font-bold font-mono tracking-tight text-primary mt-2">
                  {formatNumber(summary.total_identities)}
                </p>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="py-4">
                <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground font-semibold">Normal Baseline</CardTitle>
                <p className="text-3xl font-bold font-mono tracking-tight text-emerald-500 mt-2">
                  {formatPercent(summary.normal_pct)}
                </p>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="py-4">
                <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground font-semibold">Anomalous Activity</CardTitle>
                <div className="flex items-center gap-2 mt-2">
                  <ShieldAlert className="h-6 w-6 text-destructive" />
                  <p className="text-3xl font-bold font-mono tracking-tight text-destructive">
                    {formatPercent(summary.anomaly_pct)}
                  </p>
                </div>
              </CardHeader>
            </Card>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card className="flex flex-col">
              <CardHeader>
                <CardTitle className="text-sm font-medium">Anomaly Breakdown</CardTitle>
              </CardHeader>
              <CardContent className="flex-1">
                <div className="space-y-3">
                  {Object.entries(summary.by_label)
                    .filter(([lbl]) => lbl !== "normal")
                    .sort((a, b) => b[1] - a[1])
                    .map(([lbl, count]) => (
                      <div key={lbl} className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground font-mono">{lbl}</span>
                        <div className="flex items-center gap-3">
                          <div className="w-32 h-1.5 bg-muted rounded-full overflow-hidden">
                            <div 
                              className="h-full bg-destructive" 
                              style={{ width: `${(count / summary.anomaly_count) * 100}%` }}
                            />
                          </div>
                          <span className="text-sm font-mono w-12 text-right">{formatNumber(count)}</span>
                        </div>
                      </div>
                    ))}
                </div>
              </CardContent>
            </Card>

            <Card className="flex flex-col">
              <CardHeader>
                <CardTitle className="text-sm font-medium">Entity Type Distribution</CardTitle>
              </CardHeader>
              <CardContent className="flex-1">
                <div className="space-y-4 mt-2">
                  {Object.entries(summary.by_entity_type)
                    .sort((a, b) => b[1] - a[1])
                    .map(([type, count]) => (
                      <div key={type} className="flex items-center justify-between border-b border-border/50 pb-3 last:border-0 last:pb-0">
                        <span className="text-sm capitalize font-medium">{type.replace('_', ' ')}</span>
                        <span className="text-sm font-mono text-muted-foreground">{formatNumber(count)}</span>
                      </div>
                    ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      ) : null}

      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="text-lg">Event Telemetry</CardTitle>
        </CardHeader>
        <div className="px-6 pb-4">
          <div className="flex flex-wrap gap-4 items-center">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search resources, IPs..."
                className="pl-9"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
                data-testid="input-search"
              />
            </div>
            <Select value={entityType} onValueChange={(v) => { setEntityType(v); setPage(1); }}>
              <SelectTrigger className="w-[160px]" data-testid="select-entity-type">
                <SelectValue placeholder="Entity Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="user">User</SelectItem>
                <SelectItem value="service_account">Service Account</SelectItem>
                <SelectItem value="edge_device">Edge Device</SelectItem>
              </SelectContent>
            </Select>
            <Select value={department} onValueChange={(v) => { setDepartment(v); setPage(1); }}>
              <SelectTrigger className="w-[160px]" data-testid="select-department">
                <SelectValue placeholder="Department" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Depts</SelectItem>
                {summary && Object.keys(summary.by_department).map(dept => (
                  <SelectItem key={dept} value={dept}>{dept}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={label} onValueChange={(v) => { setLabel(v); setPage(1); }}>
              <SelectTrigger className="w-[160px]" data-testid="select-label">
                <SelectValue placeholder="Label" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Labels</SelectItem>
                {summary && Object.keys(summary.by_label).map(lbl => (
                  <SelectItem key={lbl} value={lbl}>{lbl}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="w-full overflow-auto border-t border-border/50">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-muted-foreground bg-muted/20 uppercase font-mono tracking-wider border-b border-border/50">
              <tr>
                <th className="px-4 py-3 font-medium">Timestamp</th>
                <th className="px-4 py-3 font-medium">Entity ID</th>
                <th className="px-4 py-3 font-medium">Label</th>
                <th className="px-4 py-3 font-medium">Type/Dept</th>
                <th className="px-4 py-3 font-medium">Resource/IP</th>
                <th className="px-4 py-3 font-medium">Auth</th>
                <th className="px-4 py-3 font-medium text-right">Dur (s)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50 font-mono text-xs">
              {loadingEvents ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">Loading telemetry...</td>
                </tr>
              ) : events && events.events.length > 0 ? (
                events.events.map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-muted/10 transition-colors">
                    <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">{formatDate(ev.timestamp)}</td>
                    <td className="px-4 py-3">
                      <Link href={`/identity/${ev.entity_id}`} className="text-primary hover:underline">
                        {ev.entity_id}
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant={getLabelColor(ev.label)} className="rounded-sm px-1.5 py-0.5 text-[10px] font-mono font-medium">
                        {ev.label}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-1">
                        <span className="text-foreground">{ev.entity_type}</span>
                        <span className="text-muted-foreground text-[10px]">{ev.department}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-1">
                        <span className="text-foreground max-w-[200px] truncate" title={ev.resource_accessed}>{ev.resource_accessed}</span>
                        <span className="text-muted-foreground text-[10px]">{ev.source_ip} • {ev.geo_location}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {ev.auth_success ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 text-destructive" />
                        )}
                        <span>{ev.auth_method}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right text-muted-foreground">
                      {ev.session_duration}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">No events found matching filters.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {events && events.total_pages > 1 && (
          <div className="px-6 py-4 flex items-center justify-between border-t border-border/50">
            <span className="text-sm text-muted-foreground font-mono">
              Page {events.page} of {events.total_pages}
            </span>
            <div className="flex gap-2">
              <Button 
                variant="outline" 
                size="sm" 
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
              >
                Previous
              </Button>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={() => setPage(p => Math.min(events.total_pages, p + 1))}
                disabled={page === events.total_pages}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
