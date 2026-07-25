import { useState, useEffect, useCallback } from "react";
import { Link, useLocation } from "wouter";
import {
  DetectionSummary, DetectionStatus, HighRiskEventsResponse,
  TopIdentitiesResponse, RiskTrendResponse, ScoredEvent,
  PriorityAlertsResponse, PriorityAlert, Top1Metrics,
} from "@/types";
import { AlertInvestigationDialog, AnalystDisposition } from "@/components/AlertInvestigationDialog";
import { formatNumber, formatDate, cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, CartesianGrid, PieChart, Pie, Cell, Legend,
} from "recharts";
import {
  ShieldAlert, AlertTriangle, Activity, TrendingUp, RefreshCw,
  User, Server, Cpu, ChevronRight, Target, Crosshair, Bell,
} from "lucide-react";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function riskColor(level: string) {
  switch (level) {
    case "Critical": return "text-red-500";
    case "High":     return "text-orange-500";
    case "Medium":   return "text-yellow-500";
    default:         return "text-emerald-500";
  }
}

function riskBg(level: string) {
  switch (level) {
    case "Critical": return "bg-red-500/10 text-red-500 border-red-500/30";
    case "High":     return "bg-orange-500/10 text-orange-500 border-orange-500/30";
    case "Medium":   return "bg-yellow-500/10 text-yellow-500 border-yellow-500/30";
    default:         return "bg-emerald-500/10 text-emerald-500 border-emerald-500/30";
  }
}

const RISK_COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High:     "#f97316",
  Medium:   "#eab308",
  Low:      "#10b981",
};

function EntityIcon({ type }: { type: string }) {
  if (type === "user")            return <User className="h-3.5 w-3.5" />;
  if (type === "service_account") return <Server className="h-3.5 w-3.5" />;
  return <Cpu className="h-3.5 w-3.5" />;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function SocOverview() {
  const [, setLocation] = useLocation();
  const [status, setStatus]         = useState<DetectionStatus | null>(null);
  const [summary, setSummary]       = useState<DetectionSummary | null>(null);
  const [highRisk, setHighRisk]     = useState<ScoredEvent[]>([]);
  const [topIds, setTopIds]         = useState<TopIdentitiesResponse | null>(null);
  const [trend, setTrend]           = useState<RiskTrendResponse | null>(null);
  const [priorityAlerts, setPriorityAlerts] = useState<PriorityAlertsResponse | null>(null);
  const [top1Metrics, setTop1Metrics]       = useState<Top1Metrics | null>(null);
  const [loading, setLoading]       = useState(true);
  const [running, setRunning]       = useState(false);
  const [selectedAlert, setSelectedAlert] = useState<PriorityAlert | null>(null);
  const [dispositions, setDispositions] = useState<Record<string, AnalystDisposition>>({});

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [statusRes, summaryRes, highRiskRes, topIdsRes, trendRes, alertsRes, top1Res] =
        await Promise.all([
          fetch("/sentinel-api/detection/status"),
          fetch("/sentinel-api/detection/summary"),
          fetch("/sentinel-api/detection/high-risk?limit=15"),
          fetch("/sentinel-api/detection/top-identities?limit=10"),
          fetch("/sentinel-api/detection/risk-trend"),
          fetch("/sentinel-api/detection/priority-alerts?budget_pct=1"),
          fetch("/sentinel-api/detection/top1-metrics"),
        ]);
      if (statusRes.ok)   setStatus(await statusRes.json());
      if (summaryRes.ok)  setSummary(await summaryRes.json());
      if (highRiskRes.ok) setHighRisk((await highRiskRes.json()).events ?? []);
      if (topIdsRes.ok)   setTopIds(await topIdsRes.json());
      if (trendRes.ok)    setTrend(await trendRes.json());
      if (alertsRes.ok)   setPriorityAlerts(await alertsRes.json());
      if (top1Res.ok)     setTop1Metrics(await top1Res.json());
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const handleRunDetection = async () => {
    setRunning(true);
    try {
      await fetch("/sentinel-api/detection/run?force=true", { method: "POST" });
      await fetchAll();
    } catch (err) {
      console.error(err);
    } finally {
      setRunning(false);
    }
  };

  const hasResults = status?.has_results ?? false;
  const hasTop1    = top1Metrics?.has_results ?? false;

  const pieData = summary?.by_risk_level
    ? Object.entries(summary.by_risk_level).map(([name, value]) => ({ name, value }))
    : [];

  const trendData = (trend?.trend ?? []).slice(-30).map((d) => ({
    day:       d.day.slice(5),
    anomalies: d.anomalies,
    avgRisk:   Math.round(d.avg_risk_score),
  }));

  const pct = (v?: number) => v !== undefined ? `${(v * 100).toFixed(1)}%` : "—";

  return (
    <div className="container py-8 px-4 md:px-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">SOC Overview</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            ML-powered behavioral anomaly detection dashboard.
          </p>
        </div>
        <Button
          onClick={handleRunDetection}
          disabled={running || loading}
          className="flex items-center gap-2"
          variant={hasResults ? "outline" : "default"}
        >
          <RefreshCw className={cn("h-4 w-4", (running || loading) && "animate-spin")} />
          {running ? "Running Detection…" : hasResults ? "Re-run Detection" : "Run Detection"}
        </Button>
      </div>

      {/* No results yet */}
      {!loading && !hasResults && (
        <div className="flex flex-col items-center justify-center py-20 border border-dashed border-border/60 rounded-lg text-center gap-4 bg-muted/10">
          <ShieldAlert className="h-12 w-12 text-muted-foreground" />
          <div>
            <p className="font-semibold text-foreground">No detection results yet</p>
            <p className="text-sm text-muted-foreground mt-1">
              Click <strong>Run Detection</strong> to train the Isolation Forest model and score all events.
            </p>
          </div>
        </div>
      )}

      {hasResults && summary && (
        <>
          {/* ── Step 3: Top-1% KPI Metrics ─────────────────────────────────── */}
          {hasTop1 && top1Metrics && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Target className="h-4 w-4 text-primary" />
                <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                  Priority Alert Performance — Top 1%
                </h2>
                <span className="text-[10px] text-muted-foreground border border-border/50 rounded px-1.5 py-0.5 font-mono">
                  Offline evaluation · ground truth applied after ranking
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <StatCard
                  label="Top-1% Alert Precision"
                  value={pct(top1Metrics.precision)}
                  subtitle={`${formatNumber(top1Metrics.true_positives ?? 0)} of ${formatNumber(top1Metrics.alert_count ?? 0)} alerts are real attacks`}
                  icon={<Target className="h-4 w-4" />}
                  color="text-primary"
                />
                <StatCard
                  label="Attack Coverage @ Top 1%"
                  value={pct(top1Metrics.recall)}
                  subtitle={`${formatNumber(top1Metrics.true_positives ?? 0)} of ${formatNumber(top1Metrics.total_attacks ?? 0)} true attacks captured`}
                  icon={<Crosshair className="h-4 w-4" />}
                  color="text-orange-500"
                />
                <StatCard
                  label="Top-1% Alert Count"
                  value={formatNumber(top1Metrics.alert_count ?? 0)}
                  subtitle={`of ${formatNumber(top1Metrics.total_events ?? 0)} total scored events`}
                  icon={<Bell className="h-4 w-4" />}
                  color="text-yellow-500"
                />
              </div>
            </div>
          )}

          {/* ── Original Stats row ──────────────────────────────────────────── */}
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              Detection Overview
            </h2>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard
                label="Total Scored Events"
                value={formatNumber(summary.total_scored ?? 0)}
                icon={<Activity className="h-4 w-4" />}
                color="text-primary"
              />
              <StatCard
                label="Detected Anomalies"
                value={formatNumber(summary.detected_anomalies ?? 0)}
                icon={<AlertTriangle className="h-4 w-4" />}
                color="text-orange-500"
              />
              <StatCard
                label="High / Critical Events"
                value={formatNumber(summary.high_critical_count ?? 0)}
                icon={<ShieldAlert className="h-4 w-4" />}
                color="text-red-500"
              />
              <StatCard
                label="Average Risk Score"
                value={`${summary.avg_risk_score ?? 0}`}
                icon={<TrendingUp className="h-4 w-4" />}
                color="text-yellow-500"
              />
            </div>
          </div>

          {/* ── Step 3: Priority Alert Queue ────────────────────────────────── */}
          {priorityAlerts && (priorityAlerts.alerts ?? []).length > 0 && (
            <Card className="border-red-500/20">
              <CardHeader className="pb-3 bg-red-500/5 border-b border-red-500/10">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-2">
                    <Bell className="h-4 w-4 text-red-500" />
                    <CardTitle className="text-base text-red-500">Priority Alert Queue</CardTitle>
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0 border border-red-500/30 text-red-500 bg-red-500/5">
                      Top {priorityAlerts.budget_pct}% · {formatNumber(priorityAlerts.alert_count)} alerts
                    </Badge>
                  </div>
                  <span className="text-[10px] text-muted-foreground">
                    Ranked by final risk score (ML + behavioral evidence) · no ground-truth labels used
                  </span>
                </div>
                <CardDescription className="text-xs mt-1">
                  Highest-risk {priorityAlerts.budget_pct}% of all scored events. Click an entity to open the Identity Inspector.
                </CardDescription>
              </CardHeader>
              <div className="w-full overflow-auto border-t border-border/50">
                <table className="w-full text-sm text-left">
                  <thead className="text-xs text-muted-foreground bg-muted/20 uppercase font-mono tracking-wider border-b border-border/50">
                    <tr>
                      <th className="px-3 py-3 font-medium">Timestamp</th>
                      <th className="px-3 py-3 font-medium">Entity</th>
                      <th className="px-3 py-3 font-medium">Risk Score</th>
                      <th className="px-3 py-3 font-medium">Evidence</th>
                      <th className="px-3 py-3 font-medium">Primary Reason</th>
                      <th className="px-3 py-3 font-medium">Resource / Location</th>
                      <th className="px-3 py-3 font-medium"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/50 font-mono text-xs">
                    {(priorityAlerts.alerts ?? []).slice(0, 50).map((alert: PriorityAlert) => (
                      <tr
                        key={alert.event_id}
                        className="cursor-pointer hover:bg-muted/10 transition-colors"
                        onClick={() => setSelectedAlert(alert)}
                        data-testid={`priority-alert-${alert.event_id}`}
                      >
                        <td className="px-3 py-2.5 text-muted-foreground whitespace-nowrap">
                          {formatDate(alert.timestamp)}
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="flex items-center gap-1.5">
                            <EntityIcon type={alert.entity_type} />
                            <span className="text-foreground">{alert.entity_id}</span>
                          </div>
                          <span className="text-muted-foreground text-[10px]">
                            {alert.entity_type.replace("_", " ")}
                          </span>
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="flex flex-col gap-1">
                            <span className={cn("font-bold text-sm", riskColor(alert.risk_level))}>
                              {alert.risk_score}
                            </span>
                            <Badge variant="outline" className={cn("text-[10px] px-1.5 py-0 border w-fit", riskBg(alert.risk_level))}>
                              {alert.risk_level}
                            </Badge>
                          </div>
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="flex flex-col gap-0.5">
                            <span className="text-foreground">{alert.evidence_count} signal{alert.evidence_count !== 1 ? "s" : ""}</span>
                            <span className="text-muted-foreground text-[10px]">
                              beh: {alert.behavioral_deviation_score} · ml: {alert.ml_score_norm}
                            </span>
                          </div>
                        </td>
                        <td className="px-3 py-2.5 max-w-[200px]">
                          <span className="text-muted-foreground truncate block" title={alert.primary_reason}>
                            {alert.primary_reason}
                          </span>
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="flex flex-col gap-0.5">
                            <span className="text-foreground max-w-[160px] truncate" title={alert.resource_accessed}>
                              {alert.resource_accessed}
                            </span>
                            <span className="text-muted-foreground text-[10px]">{alert.geo_location}</span>
                          </div>
                        </td>
                        <td className="px-3 py-2.5">
                          <button
                            type="button"
                            onClick={(event) => {
                              event.stopPropagation();
                              setSelectedAlert(alert);
                            }}
                            className="text-primary hover:underline text-[10px] whitespace-nowrap"
                            data-testid={`investigate-alert-${alert.event_id}`}
                          >
                            Investigate →
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {(priorityAlerts.alerts ?? []).length > 50 && (
                  <div className="px-4 py-2 border-t border-border/50 text-xs text-muted-foreground text-center">
                    Showing 50 of {formatNumber(priorityAlerts.alert_count)} priority alerts — use Model Performance for full budget analysis.
                  </div>
                )}
              </div>
            </Card>
          )}

          {/* ── Charts row ──────────────────────────────────────────────────── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Risk level distribution */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
                  Risk Level Distribution
                </CardTitle>
              </CardHeader>
              <CardContent className="h-52">
                {pieData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={3}
                        dataKey="value"
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        labelLine={false}
                      >
                        {pieData.map((entry) => (
                          <Cell key={entry.name} fill={RISK_COLORS[entry.name] ?? "#6b7280"} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 6 }}
                        itemStyle={{ color: "hsl(var(--foreground))" }}
                      />
                      <Legend iconType="circle" iconSize={8} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-muted-foreground text-sm">No data</div>
                )}
              </CardContent>
            </Card>

            {/* Risk trend */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
                  Anomaly Count Over Time
                </CardTitle>
              </CardHeader>
              <CardContent className="h-52">
                {trendData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={trendData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                      <XAxis dataKey="day" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} interval="preserveStartEnd" />
                      <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                      <Tooltip
                        contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 6 }}
                        itemStyle={{ color: "hsl(var(--foreground))" }}
                      />
                      <Line type="monotone" dataKey="anomalies" stroke="#f97316" strokeWidth={2} dot={false} name="Anomalies" />
                    </LineChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-muted-foreground text-sm">No trend data</div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* ── Bottom row ──────────────────────────────────────────────────── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Top risk identities */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Highest-Risk Identities</CardTitle>
                <CardDescription className="text-xs">Sorted by average risk score</CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                <div className="divide-y divide-border/50">
                  {(topIds?.identities ?? []).slice(0, 8).map((id) => (
                    <button
                      key={id.entity_id}
                      className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-muted/20 transition-colors text-left"
                      onClick={() => setLocation(`/identity/${id.entity_id}`)}
                    >
                      <div className="flex items-center gap-2 w-32 shrink-0">
                        <EntityIcon type={id.entity_type} />
                        <span className="font-mono text-xs font-medium truncate">{id.entity_id}</span>
                      </div>
                      <div className="flex-1 bg-muted/30 rounded-full h-1.5 overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.round(id.avg_risk_score)}%`,
                            backgroundColor: RISK_COLORS[id.max_risk_level] ?? "#6b7280",
                          }}
                        />
                      </div>
                      <span className={cn("text-xs font-mono font-bold w-8 text-right", riskColor(id.max_risk_level))}>
                        {Math.round(id.avg_risk_score)}
                      </span>
                      <Badge
                        variant="outline"
                        className={cn("text-[10px] px-1.5 py-0 border", riskBg(id.max_risk_level))}
                      >
                        {id.max_risk_level}
                      </Badge>
                      <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                    </button>
                  ))}
                  {(topIds?.identities ?? []).length === 0 && (
                    <p className="px-4 py-6 text-sm text-muted-foreground text-center">No data</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Top risk bar chart */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base">Top Identity Risk Scores</CardTitle>
                <CardDescription className="text-xs">Average risk score per identity</CardDescription>
              </CardHeader>
              <CardContent className="h-56">
                {(topIds?.identities ?? []).length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={(topIds?.identities ?? []).slice(0, 8).map((id) => ({
                        id:    id.entity_id.replace("_", " "),
                        score: Math.round(id.avg_risk_score),
                        level: id.max_risk_level,
                      }))}
                      margin={{ top: 4, right: 8, left: -20, bottom: 24 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                      <XAxis dataKey="id" tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }} angle={-30} textAnchor="end" interval={0} />
                      <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                      <Tooltip
                        contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 6 }}
                        itemStyle={{ color: "hsl(var(--foreground))" }}
                      />
                      <Bar dataKey="score" name="Avg Risk Score" radius={[4, 4, 0, 0]}>
                        {(topIds?.identities ?? []).slice(0, 8).map((id) => (
                          <Cell key={id.entity_id} fill={RISK_COLORS[id.max_risk_level] ?? "#6b7280"} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-muted-foreground text-sm">No data</div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* ── Recent High-Risk Events table ────────────────────────────────── */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Recent High-Risk Events</CardTitle>
              <CardDescription className="text-xs">High and Critical severity events, sorted by risk score</CardDescription>
            </CardHeader>
            <div className="w-full overflow-auto border-t border-border/50">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-muted-foreground bg-muted/20 uppercase font-mono tracking-wider border-b border-border/50">
                  <tr>
                    <th className="px-4 py-3 font-medium">Timestamp</th>
                    <th className="px-4 py-3 font-medium">Entity</th>
                    <th className="px-4 py-3 font-medium">Risk</th>
                    <th className="px-4 py-3 font-medium">Resource / Location</th>
                    <th className="px-4 py-3 font-medium">Primary Reason</th>
                    <th className="px-4 py-3 font-medium"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50 font-mono text-xs">
                  {highRisk.length > 0 ? (
                    highRisk.map((ev) => (
                      <tr key={ev.event_id} className="hover:bg-muted/10 transition-colors">
                        <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">
                          {formatDate(ev.timestamp)}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1.5">
                            <EntityIcon type={ev.entity_type} />
                            <span className="text-foreground">{ev.entity_id}</span>
                          </div>
                          <span className="text-muted-foreground text-[10px]">{ev.entity_type.replace("_", " ")}</span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-col gap-1">
                            <span className={cn("font-bold text-sm", riskColor(ev.risk_level))}>
                              {ev.risk_score}
                            </span>
                            <Badge variant="outline" className={cn("text-[10px] px-1.5 py-0 border w-fit", riskBg(ev.risk_level))}>
                              {ev.risk_level}
                            </Badge>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-col gap-0.5">
                            <span className="text-foreground max-w-[200px] truncate" title={ev.resource_accessed}>
                              {ev.resource_accessed}
                            </span>
                            <span className="text-muted-foreground text-[10px]">{ev.geo_location}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 max-w-[220px]">
                          {ev.reasons && ev.reasons.length > 0 ? (
                            <span className="text-muted-foreground">{ev.reasons[0]}</span>
                          ) : "—"}
                        </td>
                        <td className="px-4 py-3">
                          <Link href={`/identity/${ev.entity_id}`}>
                            <button className="text-primary hover:underline text-[10px] whitespace-nowrap">
                              View →
                            </button>
                          </Link>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                        No high-risk events found.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}

      {loading && (
        <div className="space-y-4 animate-pulse">
          <div className="grid grid-cols-3 gap-4">{[...Array(3)].map((_, i) => <div key={i} className="h-24 bg-muted/30 rounded-lg border border-border/50" />)}</div>
          <div className="grid grid-cols-4 gap-4">{[...Array(4)].map((_, i) => <div key={i} className="h-24 bg-muted/30 rounded-lg border border-border/50" />)}</div>
          <div className="h-64 bg-muted/30 rounded-lg border border-border/50" />
          <div className="grid grid-cols-2 gap-4">{[...Array(2)].map((_, i) => <div key={i} className="h-52 bg-muted/30 rounded-lg border border-border/50" />)}</div>
          <div className="h-64 bg-muted/30 rounded-lg border border-border/50" />
        </div>
      )}

      <AlertInvestigationDialog
        alert={selectedAlert}
        disposition={selectedAlert ? dispositions[selectedAlert.event_id] : undefined}
        onDispositionChange={(disposition) => {
          if (selectedAlert) {
            setDispositions((current) => ({
              ...current,
              [selectedAlert.event_id]: disposition,
            }));
          }
        }}
        onClose={() => setSelectedAlert(null)}
      />
    </div>
  );
}

function StatCard({
  label, value, subtitle, icon, color,
}: { label: string; value: string; subtitle?: string; icon: React.ReactNode; color: string }) {
  return (
    <Card>
      <CardContent className="pt-4 pb-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</span>
          <span className={cn("opacity-70", color)}>{icon}</span>
        </div>
        <p className={cn("text-3xl font-mono font-bold", color)}>{value}</p>
        {subtitle && <p className="text-[11px] text-muted-foreground mt-1 leading-snug">{subtitle}</p>}
      </CardContent>
    </Card>
  );
}
