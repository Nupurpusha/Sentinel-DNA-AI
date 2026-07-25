import { useState, useEffect } from "react";
import { ModelMetrics, AlertBudgetResponse, AttackCoverageResponse, DetectionStatus } from "@/types";
import { formatNumber, cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RefreshCw, ShieldCheck, AlertTriangle, Info, CheckCircle2, XCircle, Shield } from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";

function MetricCard({
  label, value, description, color = "text-primary",
}: {
  label: string; value: string | number; description?: string; color?: string;
}) {
  return (
    <Card>
      <CardContent className="pt-5 pb-5">
        <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-1">{label}</p>
        <p className={cn("text-3xl font-mono font-bold", color)}>{value}</p>
        {description && <p className="text-xs text-muted-foreground mt-1">{description}</p>}
      </CardContent>
    </Card>
  );
}

export function ModelPerformance() {
  const [metrics, setMetrics]   = useState<ModelMetrics | null>(null);
  const [budget, setBudget]     = useState<AlertBudgetResponse | null>(null);
  const [coverage, setCoverage] = useState<AttackCoverageResponse | null>(null);
  const [status, setStatus]     = useState<DetectionStatus | null>(null);
  const [loading, setLoading]   = useState(true);
  const [running, setRunning]   = useState(false);

  const fetchAll = async () => {
    setLoading(true);
    try {
      const [metricsRes, budgetRes, coverageRes, statusRes] = await Promise.all([
        fetch("/sentinel-api/detection/metrics"),
        fetch("/sentinel-api/detection/alert-budget"),
        fetch("/sentinel-api/detection/attack-coverage"),
        fetch("/sentinel-api/detection/status"),
      ]);
      if (metricsRes.ok)   setMetrics(await metricsRes.json());
      if (budgetRes.ok)    setBudget(await budgetRes.json());
      if (coverageRes.ok)  setCoverage(await coverageRes.json());
      if (statusRes.ok)    setStatus(await statusRes.json());
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchAll(); }, []);

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

  const hasResults = metrics?.has_results ?? false;
  const leakagePassed = status?.label_leakage_test_passed ?? false;

  const cmData = hasResults
    ? [
        { label: "True Positives",  value: metrics!.true_positives ?? 0,  color: "#10b981" },
        { label: "False Positives", value: metrics!.false_positives ?? 0, color: "#f97316" },
        { label: "False Negatives", value: metrics!.false_negatives ?? 0, color: "#ef4444" },
        { label: "True Negatives",  value: metrics!.true_negatives ?? 0,  color: "#6b7280" },
      ]
    : [];

  const pct = (v?: number) =>
    v !== undefined ? `${(v * 100).toFixed(1)}%` : "—";

  const budgetPctColor = (pct: number) => {
    if (pct >= 0.6)  return "text-emerald-500";
    if (pct >= 0.35) return "text-yellow-500";
    return "text-orange-500";
  };

  return (
    <div className="container py-8 px-4 md:px-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">Model Performance</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            Isolation Forest evaluation metrics — using ground-truth labels for offline validation only.
          </p>
        </div>
        <Button
          onClick={handleRunDetection}
          disabled={running || loading}
          variant={hasResults ? "outline" : "default"}
          className="flex items-center gap-2"
        >
          <RefreshCw className={cn("h-4 w-4", (running || loading) && "animate-spin")} />
          {running ? "Running…" : hasResults ? "Re-run Detection" : "Run Detection"}
        </Button>
      </div>

      {/* Data leakage notice */}
      <div className="flex items-start gap-3 px-4 py-3 rounded-lg border border-primary/20 bg-primary/5 text-sm">
        <Info className="h-4 w-4 text-primary mt-0.5 shrink-0" />
        <div>
          <span className="font-semibold text-primary">Data leakage prevention:</span>{" "}
          <span className="text-muted-foreground">
            Ground-truth attack labels (<code className="text-xs font-mono bg-muted/30 px-1 py-0.5 rounded">normal</code>,{" "}
            <code className="text-xs font-mono bg-muted/30 px-1 py-0.5 rounded">brute_force</code>, …) are{" "}
            <strong>never</strong> used as model inputs or for scoring. They are used
            exclusively here, after predictions have been generated, for offline evaluation.
          </span>
        </div>
      </div>

      {!loading && !hasResults && (
        <div className="flex flex-col items-center justify-center py-20 border border-dashed border-border/60 rounded-lg text-center gap-4 bg-muted/10">
          <ShieldCheck className="h-12 w-12 text-muted-foreground" />
          <div>
            <p className="font-semibold text-foreground">No results yet</p>
            <p className="text-sm text-muted-foreground mt-1">
              Run the detection engine first to generate model metrics.
            </p>
          </div>
        </div>
      )}

      {loading && (
        <div className="space-y-4 animate-pulse">
          <div className="grid grid-cols-3 gap-4">{[...Array(3)].map((_, i) => <div key={i} className="h-24 bg-muted/30 rounded-lg border border-border/50" />)}</div>
          <div className="grid grid-cols-2 gap-4">{[...Array(2)].map((_, i) => <div key={i} className="h-32 bg-muted/30 rounded-lg border border-border/50" />)}</div>
          <div className="h-48 bg-muted/30 rounded-lg border border-border/50" />
          <div className="h-48 bg-muted/30 rounded-lg border border-border/50" />
        </div>
      )}

      {!loading && hasResults && metrics && (
        <>
          {/* ── Label Leakage Test ───────────────────────────────────────────── */}
          <div className="flex items-center gap-3 px-4 py-3 rounded-lg border border-border/50 bg-muted/5">
            <Shield className="h-4 w-4 text-muted-foreground shrink-0" />
            <div className="flex-1">
              <span className="text-sm font-medium">Label Leakage Validation Test</span>
              <p className="text-xs text-muted-foreground mt-0.5">
                Proves that shuffling/replacing ground-truth labels produces identical ML scores,
                behavioral deviation scores, evidence counts, final risk scores, and event rankings.
              </p>
            </div>
            {leakagePassed ? (
              <div className="flex items-center gap-1.5 shrink-0">
                <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                <span className="text-sm font-semibold text-emerald-500 font-mono">PASSED</span>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 shrink-0">
                <XCircle className="h-4 w-4 text-red-500" />
                <span className="text-sm font-semibold text-red-500 font-mono">
                  {status ? "FAILED" : "UNKNOWN"}
                </span>
              </div>
            )}
          </div>

          {/* ── Original model metrics (Step 2, preserved) ───────────────────── */}
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              Raw Detector Metrics — Isolation Forest with IF threshold (contamination = 5%)
            </h2>
            <p className="text-xs text-muted-foreground mb-3">
              These metrics reflect the <strong>raw Isolation Forest decision boundary</strong> at contamination=0.05.
              High recall, lower precision — expected for an unsupervised anomaly detector at 5% flagging rate.
              See the SOC Alert Budget section below for operational precision at reduced alert volumes.
            </p>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
              <MetricCard label="Precision" value={pct(metrics.precision)} color="text-primary"
                description="Fraction of predicted anomalies that are real" />
              <MetricCard label="Recall" value={pct(metrics.recall)} color="text-orange-500"
                description="Fraction of real anomalies detected" />
              <MetricCard label="F1 Score" value={pct(metrics.f1_score)} color="text-yellow-500"
                description="Harmonic mean of precision and recall" />
              {metrics.roc_auc != null && (
                <MetricCard label="ROC-AUC" value={metrics.roc_auc.toFixed(3)} color="text-emerald-500"
                  description="Area under the ROC curve — ranking quality" />
              )}
            </div>
          </div>

          {/* Confusion matrix counts */}
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              Detection Counts — Raw Detector
            </h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <MetricCard label="True Positives" value={formatNumber(metrics.true_positives ?? 0)} color="text-emerald-500"
                description="Anomalies correctly flagged" />
              <MetricCard label="False Positives" value={formatNumber(metrics.false_positives ?? 0)} color="text-orange-500"
                description="Normal events incorrectly flagged" />
              <MetricCard label="False Negatives" value={formatNumber(metrics.false_negatives ?? 0)} color="text-red-500"
                description="Anomalies missed by model" />
              <MetricCard label="True Negatives" value={formatNumber(metrics.true_negatives ?? 0)} color="text-muted-foreground"
                description="Normal events correctly cleared" />
            </div>
          </div>

          {/* Charts row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
                  Confusion Matrix Breakdown
                </CardTitle>
              </CardHeader>
              <CardContent className="h-52">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={cmData} margin={{ top: 4, right: 8, left: -10, bottom: 0 }}>
                    <XAxis dataKey="label" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                    <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                    <Tooltip
                      contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 6 }}
                      itemStyle={{ color: "hsl(var(--foreground))" }}
                    />
                    <Bar dataKey="value" name="Count" radius={[4, 4, 0, 0]}>
                      {cmData.map((entry) => (
                        <Cell key={entry.label} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
                  Coverage Summary
                </CardTitle>
                <CardDescription className="text-xs">Ground-truth comparison (post-hoc only)</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4 pt-2">
                <CoverageRow
                  label="True Anomalies in Dataset"
                  value={formatNumber(metrics.total_true_anomalies ?? 0)}
                  note="From label column"
                  icon={<AlertTriangle className="h-4 w-4 text-red-500" />}
                />
                <CoverageRow
                  label="Predicted Anomalies by Model"
                  value={formatNumber(metrics.total_predicted_anomalies ?? 0)}
                  note="From Isolation Forest"
                  icon={<ShieldCheck className="h-4 w-4 text-primary" />}
                />
                <CoverageRow
                  label="Correctly Detected"
                  value={formatNumber(metrics.true_positives ?? 0)}
                  note={`${pct((metrics.true_positives ?? 0) / Math.max(metrics.total_true_anomalies ?? 1, 1))} of true anomalies`}
                  icon={<ShieldCheck className="h-4 w-4 text-emerald-500" />}
                />
                {metrics.note && (
                  <p className="text-[11px] text-muted-foreground border-t border-border/50 pt-3 leading-relaxed">
                    {metrics.note}
                  </p>
                )}
              </CardContent>
            </Card>
          </div>

          {/* ── Step 3: SOC Alert Budget Analysis ───────────────────────────── */}
          {budget?.has_results && budget.budgets && (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <CardTitle className="text-base">SOC Alert Budget Analysis</CardTitle>
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 border border-primary/30 text-primary">
                    Step 3
                  </Badge>
                </div>
                <CardDescription className="text-xs mt-1">
                  {budget.note ??
                    "Events are ranked using unsupervised behavioral risk. Ground-truth labels are applied only after ranking for offline evaluation."}
                </CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-auto">
                  <table className="w-full text-sm text-left">
                    <thead className="text-xs text-muted-foreground bg-muted/20 uppercase font-mono tracking-wider border-y border-border/50">
                      <tr>
                        <th className="px-4 py-3 font-medium">Alert Budget</th>
                        <th className="px-4 py-3 font-medium">Alert Count</th>
                        <th className="px-4 py-3 font-medium">Precision</th>
                        <th className="px-4 py-3 font-medium">Recall</th>
                        <th className="px-4 py-3 font-medium">F1</th>
                        <th className="px-4 py-3 font-medium">True Pos</th>
                        <th className="px-4 py-3 font-medium">False Pos</th>
                        <th className="px-4 py-3 font-medium">False Neg</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/50 font-mono text-xs">
                      {budget.budgets.map((row) => (
                        <tr
                          key={row.budget_pct}
                          className={cn(
                            "hover:bg-muted/10 transition-colors",
                            row.budget_pct === 1.0 && "bg-primary/5 border-l-2 border-l-primary",
                          )}
                        >
                          <td className="px-4 py-3 font-medium">
                            Top {row.budget_pct}%
                            {row.budget_pct === 1.0 && (
                              <span className="ml-1.5 text-[9px] uppercase tracking-wider text-primary font-semibold">Primary</span>
                            )}
                          </td>
                          <td className="px-4 py-3">{formatNumber(row.alert_count)}</td>
                          <td className={cn("px-4 py-3 font-bold", budgetPctColor(row.precision))}>
                            {pct(row.precision)}
                          </td>
                          <td className="px-4 py-3">{pct(row.recall)}</td>
                          <td className="px-4 py-3">{pct(row.f1_score)}</td>
                          <td className="px-4 py-3 text-emerald-500">{formatNumber(row.true_positives)}</td>
                          <td className="px-4 py-3 text-orange-500">{formatNumber(row.false_positives)}</td>
                          <td className="px-4 py-3 text-red-500">{formatNumber(row.false_negatives)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="px-4 py-2 border-t border-border/50 text-[11px] text-muted-foreground">
                  Total events: {formatNumber(budget.total_events ?? 0)} · True attacks: {formatNumber(budget.total_attacks ?? 0)}
                </div>
              </CardContent>
            </Card>
          )}

          {/* ── Step 3: Detection Coverage by Attack Type ────────────────────── */}
          {coverage?.has_results && coverage.coverage && (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <CardTitle className="text-base">Detection Coverage by Attack Type</CardTitle>
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 border border-primary/30 text-primary">
                    Top 1% · Offline Evaluation
                  </Badge>
                </div>
                <CardDescription className="text-xs mt-1">
                  {coverage.note ??
                    "Shows which attack behaviors SentinelDNA detects particularly well within the top-1% alert budget. Attack categories are applied ONLY after ranking."}
                </CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-auto">
                  <table className="w-full text-sm text-left">
                    <thead className="text-xs text-muted-foreground bg-muted/20 uppercase font-mono tracking-wider border-y border-border/50">
                      <tr>
                        <th className="px-4 py-3 font-medium">Attack Type</th>
                        <th className="px-4 py-3 font-medium">Total GT Events</th>
                        <th className="px-4 py-3 font-medium">Captured in Top 1%</th>
                        <th className="px-4 py-3 font-medium">Coverage</th>
                        <th className="px-4 py-3 font-medium w-40">Detection Bar</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/50 font-mono text-xs">
                      {coverage.coverage.map((row) => {
                        const coverageColor =
                          row.coverage_pct >= 70 ? "bg-emerald-500" :
                          row.coverage_pct >= 40 ? "bg-yellow-500" :
                          "bg-orange-500";
                        const textColor =
                          row.coverage_pct >= 70 ? "text-emerald-500" :
                          row.coverage_pct >= 40 ? "text-yellow-500" :
                          "text-orange-500";
                        return (
                          <tr key={row.attack_type} className="hover:bg-muted/10 transition-colors">
                            <td className="px-4 py-3 font-medium">
                              <code className="text-xs bg-muted/30 px-1.5 py-0.5 rounded">
                                {row.attack_type}
                              </code>
                            </td>
                            <td className="px-4 py-3 text-muted-foreground">{formatNumber(row.total_gt)}</td>
                            <td className="px-4 py-3">{formatNumber(row.captured_top1)}</td>
                            <td className={cn("px-4 py-3 font-bold", textColor)}>
                              {row.coverage_pct.toFixed(1)}%
                            </td>
                            <td className="px-4 py-3">
                              <div className="w-full bg-muted/30 rounded-full h-1.5 overflow-hidden">
                                <div
                                  className={cn("h-full rounded-full", coverageColor)}
                                  style={{ width: `${row.coverage_pct}%` }}
                                />
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <div className="px-4 py-2 border-t border-border/50 text-[11px] text-muted-foreground">
                  Alert budget: top {coverage.budget_pct}% = {formatNumber(coverage.alert_count ?? 0)} events
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

function CoverageRow({
  label, value, note, icon,
}: { label: string; value: string; note?: string; icon?: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3">
      <div className="shrink-0">{icon}</div>
      <div className="flex-1">
        <p className="text-sm font-medium">{label}</p>
        {note && <p className="text-xs text-muted-foreground">{note}</p>}
      </div>
      <span className="font-mono font-bold text-lg">{value}</span>
    </div>
  );
}
