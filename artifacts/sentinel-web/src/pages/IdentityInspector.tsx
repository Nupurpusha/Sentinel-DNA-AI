import { useState, useEffect } from "react";
import { useParams, useLocation } from "wouter";
import { IdentityResponse, IdentitiesResponse, IdentityRisk, ScoredEvent, TemporalDrift, SequenceScore } from "@/types";
import { formatNumber, formatDate, cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import {
  User, Server, MapPin, Clock, Fingerprint, Lock,
  CheckCircle2, XCircle, ShieldAlert, AlertTriangle, Activity, Network,
} from "lucide-react";

// ─── Risk helpers ─────────────────────────────────────────────────────────────

function riskColor(level: string) {
  switch (level) {
    case "Critical": return "text-red-500";
    case "High":     return "text-orange-500";
    case "Medium":   return "text-yellow-500";
    default:         return "text-emerald-500";
  }
}

function riskBadgeClass(level: string) {
  switch (level) {
    case "Critical": return "bg-red-500/10 text-red-500 border-red-500/30";
    case "High":     return "bg-orange-500/10 text-orange-500 border-orange-500/30";
    case "Medium":   return "bg-yellow-500/10 text-yellow-500 border-yellow-500/30";
    default:         return "bg-emerald-500/10 text-emerald-500 border-emerald-500/30";
  }
}

function scoreColor(score: number) {
  if (score >= 76) return "text-red-500";
  if (score >= 51) return "text-orange-500";
  if (score >= 26) return "text-yellow-500";
  return "text-emerald-500";
}

function riskLevel(score: number) {
  if (score >= 76) return "Critical";
  if (score >= 51) return "High";
  if (score >= 26) return "Medium";
  return "Low";
}

// ─── Component ────────────────────────────────────────────────────────────────

export function IdentityInspector() {
  const { entityId } = useParams();
  const [, setLocation] = useLocation();

  const [identities, setIdentities] = useState<IdentitiesResponse | null>(null);
  const [loadingList, setLoadingList] = useState(true);

  const [data, setData] = useState<IdentityResponse | null>(null);
  const [loadingData, setLoadingData] = useState(false);

  const [risk, setRisk] = useState<IdentityRisk | null>(null);
  const [loadingRisk, setLoadingRisk] = useState(false);

  const [drift, setDrift] = useState<TemporalDrift | null>(null);
  const [seqScore, setSeqScore] = useState<SequenceScore | null>(null);

  useEffect(() => {
    const fetchIdentities = async () => {
      setLoadingList(true);
      try {
        const res = await fetch("/sentinel-api/identities");
        if (res.ok) {
          const json = await res.json();
          setIdentities(json);
          if (!entityId && json.identities && json.identities.length > 0) {
            setLocation(`/identity/${json.identities[0].entity_id}`);
          }
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoadingList(false);
      }
    };
    fetchIdentities();
  }, [entityId, setLocation]);

  useEffect(() => {
    if (!entityId) return;

    const fetchIdentityData = async () => {
      setLoadingData(true);
      try {
        const res = await fetch(`/sentinel-api/identities/${entityId}`);
        if (res.ok) setData(await res.json());
        else setData(null);
      } catch (err) {
        console.error(err);
        setData(null);
      } finally {
        setLoadingData(false);
      }
    };

    const fetchRisk = async () => {
      setLoadingRisk(true);
      try {
        const res = await fetch(`/sentinel-api/identities/${entityId}/risk`);
        if (res.ok) setRisk(await res.json());
        else setRisk(null);
      } catch (err) {
        console.error(err);
        setRisk(null);
      } finally {
        setLoadingRisk(false);
      }
    };

    const fetchDrift = async () => {
      try {
        const res = await fetch(`/sentinel-api/detection/temporal/${entityId}`);
        if (res.ok) setDrift(await res.json());
        else setDrift(null);
      } catch {
        setDrift(null);
      }
    };

    const fetchSeqScore = async () => {
      try {
        const res = await fetch(`/sentinel-api/detection/sequence/${entityId}`);
        if (res.ok) setSeqScore(await res.json());
        else setSeqScore(null);
      } catch {
        setSeqScore(null);
      }
    };

    fetchIdentityData();
    fetchRisk();
    fetchDrift();
    fetchSeqScore();
  }, [entityId]);

  const getLabelColor = (lbl: string) => {
    if (lbl === "normal") return "success";
    if (lbl.includes("drift") || lbl.includes("spoofing")) return "warning";
    return "destructive";
  };

  const formatHours = (hours: number[]) => {
    if (!hours || hours.length === 0) return "N/A";
    const start = Math.min(...hours);
    const end = Math.max(...hours);
    return `${start}:00 - ${end}:00`;
  };

  return (
    <div className="container py-8 px-4 md:px-8 max-w-7xl mx-auto space-y-6">
      {/* Page header + entity selector */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">Identity Inspector</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            Analyze behavioral baselines and event history for specific entities.
          </p>
        </div>

        <div className="w-full md:w-80">
          <Select
            value={entityId || ""}
            onValueChange={(v) => setLocation(`/identity/${v}`)}
            disabled={loadingList}
          >
            <SelectTrigger data-testid="select-entity">
              <SelectValue placeholder="Select an entity..." />
            </SelectTrigger>
            <SelectContent>
              {identities?.identities.map((id) => (
                <SelectItem key={id.entity_id} value={id.entity_id}>
                  <span className="font-mono text-xs">{id.entity_id}</span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {!entityId ? (
        <div className="text-center py-20 text-muted-foreground bg-card border border-border/50 rounded-lg">
          Please select an identity to view its profile.
        </div>
      ) : loadingData ? (
        <div className="space-y-6 animate-pulse">
          <div className="h-64 bg-muted/50 rounded-lg border border-border/50" />
          <div className="h-96 bg-muted/50 rounded-lg border border-border/50" />
        </div>
      ) : data ? (
        <div className="space-y-6">
          {/* ── Behavioral Profile Card ─────────────────────────────────────── */}
          <Card className="border-primary/20 shadow-lg shadow-primary/5">
            <CardHeader className="bg-muted/10 border-b border-border/50 pb-6">
              <div className="flex items-start justify-between flex-wrap gap-4">
                <div className="flex items-center gap-4">
                  <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center border border-primary/20 text-primary">
                    {data.identity.entity_type === "user" ? (
                      <User className="h-6 w-6" />
                    ) : (
                      <Server className="h-6 w-6" />
                    )}
                  </div>
                  <div>
                    <CardTitle className="text-2xl font-mono text-primary">
                      {data.identity.entity_id}
                    </CardTitle>
                    <CardDescription className="uppercase tracking-widest text-xs mt-1 font-semibold flex items-center gap-2">
                      <span>{data.identity.entity_type.replace("_", " ")}</span>
                      {data.identity.department && (
                        <>
                          <span className="w-1 h-1 rounded-full bg-muted-foreground" />
                          <span>{data.identity.department}</span>
                        </>
                      )}
                    </CardDescription>
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      <Badge
                        variant="outline"
                        className={cn(
                          "text-[10px]",
                          data.baseline_status === "Cold Start"
                            ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-400"
                            : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
                        )}
                      >
                        {data.baseline_status ?? "Established"} baseline
                      </Badge>
                      <span className="text-[10px] text-muted-foreground">
                        {data.history_event_count ?? data.event_count} historical events
                      </span>
                    </div>
                  </div>
                </div>

                {/* Risk summary (right side of header) */}
                <div className="flex items-center gap-4">
                  {risk?.has_results && (
                    <div className="text-right">
                      <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">
                        Final Risk Score
                      </p>
                      <div className="flex items-center gap-2 justify-end">
                        <span className={cn("text-2xl font-mono font-bold", riskColor(risk.risk_level ?? "Low"))}>
                          {risk.avg_risk_score}
                        </span>
                        <Badge
                          variant="outline"
                          className={cn("text-xs border", riskBadgeClass(risk.risk_level ?? "Low"))}
                        >
                          {risk.risk_level}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        {formatNumber(risk.detected_anomalies ?? 0)} anomalous events detected
                      </p>
                      {risk.avg_behavioral_deviation != null && (
                        <div className="flex items-center gap-2 justify-end mt-1.5">
                          <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Behavioral Dev:</span>
                          <span className="text-xs font-mono font-semibold text-orange-400">{risk.avg_behavioral_deviation}</span>
                          {risk.avg_evidence_count != null && (
                            <>
                              <span className="text-muted-foreground text-[10px]">·</span>
                              <span className="text-[10px] text-muted-foreground">avg {risk.avg_evidence_count?.toFixed(1)} signals</span>
                            </>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                  <div className="text-right border-l border-border/50 pl-4">
                    <p className="text-sm text-muted-foreground">Baseline Events</p>
                    <p className="text-2xl font-mono font-bold">{formatNumber(data.event_count)}</p>
                  </div>
                </div>
              </div>
            </CardHeader>
            {data.baseline_status === "Cold Start" && (
              <div className="border-b border-yellow-500/20 bg-yellow-500/5 px-6 py-3 text-xs text-yellow-200">
                <strong>Cold Start:</strong> this identity has only{" "}
                {data.history_event_count ?? data.event_count} historical events.
                Behavioral deviations are not considered reliable until{" "}
                {data.minimum_history_events ?? 50} events are available.
              </div>
            )}

            <CardContent className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 p-6">
              <div className="space-y-4">
                <div className="flex gap-3">
                  <Clock className="h-5 w-5 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-sm font-medium">Active Hours (UTC)</p>
                    <p className="text-sm text-muted-foreground font-mono mt-1 bg-muted/30 inline-block px-2 py-1 rounded">
                      {formatHours(data.identity.profile.normal_hours)}
                    </p>
                  </div>
                </div>
                <div className="flex gap-3">
                  <MapPin className="h-5 w-5 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-sm font-medium">Primary Location</p>
                    <p className="text-sm text-muted-foreground mt-1">
                      {data.identity.profile.primary_location}
                    </p>
                    {data.identity.profile.ip_prefix && (
                      <p className="text-xs text-muted-foreground font-mono mt-1">
                        IP: {data.identity.profile.ip_prefix}.*
                      </p>
                    )}
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex gap-3">
                  <Fingerprint className="h-5 w-5 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-sm font-medium">Known Devices</p>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {data.identity.profile.known_devices.map((dev) => (
                        <Badge key={dev} variant="secondary" className="font-mono text-[10px]">
                          {dev}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="flex gap-3">
                  <Lock className="h-5 w-5 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-sm font-medium">Auth Profile</p>
                    <p className="text-sm text-muted-foreground mt-1">
                      Preferred: <span className="font-mono">{data.identity.profile.preferred_auth}</span>
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Avg Session: {data.identity.profile.session_dur_min}s –{" "}
                      {data.identity.profile.session_dur_max}s
                    </p>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex gap-3">
                  <Server className="h-5 w-5 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-sm font-medium">Common Resources</p>
                    <ul className="mt-2 space-y-1">
                      {data.identity.profile.common_resources.map((res) => (
                        <li
                          key={res}
                          className="text-xs text-muted-foreground font-mono truncate max-w-[200px]"
                          title={res}
                        >
                          {res}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* ── Temporal Drift ──────────────────────────────────────────────── */}
          {(() => {
            if (!drift) return null;

            // Cold-start case
            if (drift.baseline_status === "Cold Start") {
              return (
                <Card className="border-yellow-500/30">
                  <CardHeader className="pb-3 bg-yellow-500/5 border-b border-yellow-500/15">
                    <div className="flex items-center gap-2">
                      <Activity className="h-5 w-5 text-yellow-400" />
                      <CardTitle className="text-base text-yellow-400">Temporal Drift Analysis</CardTitle>
                    </div>
                  </CardHeader>
                  <CardContent className="pt-4">
                    <div className="flex items-center gap-3 rounded-lg border border-yellow-500/30 bg-yellow-500/5 px-4 py-3">
                      <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0" />
                      <div>
                        <p className="text-sm font-semibold text-yellow-300">Cold Start — insufficient behavioral history</p>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Only {drift.history_event_count} events recorded; temporal drift scoring requires at least {drift.minimum_history_events}.
                          Drift metrics will become available once sufficient history is collected.
                          A score of 0 does <strong>not</strong> indicate this identity is safe.
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            }

            // Established baseline — show drift tier + reasons
            const tierColor =
              drift.temporal_status === "High Drift"  ? "text-red-400 border-red-500/30 bg-red-500/10" :
              drift.temporal_status === "Elevated"    ? "text-yellow-400 border-yellow-500/30 bg-yellow-500/10" :
              "text-emerald-400 border-emerald-500/30 bg-emerald-500/10";
            const barColor =
              drift.temporal_status === "High Drift"  ? "bg-red-500" :
              drift.temporal_status === "Elevated"    ? "bg-yellow-500" :
              "bg-emerald-500";
            const cardBorder =
              drift.temporal_status === "High Drift"  ? "border-red-500/20" :
              drift.temporal_status === "Elevated"    ? "border-yellow-500/20" :
              "border-emerald-500/20";

            return (
              <Card className={cardBorder}>
                <CardHeader className="pb-3 border-b border-border/50">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Activity className="h-5 w-5 text-muted-foreground" />
                      <CardTitle className="text-base">Temporal Drift Analysis</CardTitle>
                    </div>
                    <Badge variant="outline" className={cn("text-xs border px-2.5 py-0.5", tierColor)}>
                      {drift.temporal_status}
                    </Badge>
                  </div>
                  <CardDescription className="text-xs mt-1">
                    Behavioral drift score derived from multi-signal temporal analysis. Labels are never used.
                  </CardDescription>
                </CardHeader>
                <CardContent className="pt-4 space-y-3">
                  {/* Score bar */}
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-muted-foreground uppercase tracking-wider">Drift Score</span>
                      <span className={cn("font-mono font-bold text-sm", tierColor.split(" ")[0])}>
                        {drift.temporal_drift_score} / 100
                      </span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-muted/30 overflow-hidden">
                      <div
                        className={cn("h-full rounded-full transition-all", barColor)}
                        style={{ width: `${Math.min(drift.temporal_drift_score, 100)}%` }}
                      />
                    </div>
                    <div className="flex justify-between mt-1 text-[10px] text-muted-foreground/60">
                      <span>Stable (&lt;35)</span><span>Elevated (35–64)</span><span>High Drift (≥65)</span>
                    </div>
                  </div>

                  {/* Reasons */}
                  {drift.temporal_reasons.length > 0 ? (
                    <ul className="space-y-1.5">
                      {drift.temporal_reasons.map((reason) => (
                        <li key={reason} className="flex items-start gap-2 text-xs text-foreground/85">
                          <AlertTriangle className="h-3 w-3 text-yellow-400 mt-0.5 shrink-0" />
                          {reason}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-muted-foreground">No significant drift signals detected in recent activity windows.</p>
                  )}
                </CardContent>
              </Card>
            );
          })()}

          {/* ── Sequence Anomaly Score ──────────────────────────────────────── */}
          {(() => {
            if (!seqScore) return null;

            if (!seqScore.reliable) {
              return (
                <Card className="border-yellow-500/30">
                  <CardHeader className="pb-3 bg-yellow-500/5 border-b border-yellow-500/15">
                    <div className="flex items-center gap-2">
                      <Network className="h-5 w-5 text-yellow-400" />
                      <CardTitle className="text-base text-yellow-400">Sequence Anomaly Score</CardTitle>
                    </div>
                  </CardHeader>
                  <CardContent className="pt-4">
                    <div className="flex items-center gap-3 rounded-lg border border-yellow-500/30 bg-yellow-500/5 px-4 py-3">
                      <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0" />
                      <div>
                        <p className="text-sm font-semibold text-yellow-300">Cold Start — insufficient behavioral history</p>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Only {seqScore.history_event_count} events recorded; GRU sequence scoring requires at least{" "}
                          {seqScore.minimum_history_events} chronological events to establish a reliable baseline.
                          {seqScore.message && ` ${seqScore.message}`}
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            }

            const score = seqScore.score ?? 0;
            const seqBorderColor =
              score >= 80 ? "border-red-500/20" :
              score >= 50 ? "border-orange-500/20" :
              score >= 25 ? "border-yellow-500/20" :
              "border-emerald-500/20";
            const seqBarColor =
              score >= 80 ? "bg-red-500" :
              score >= 50 ? "bg-orange-500" :
              score >= 25 ? "bg-yellow-500" :
              "bg-emerald-500";
            const seqTextColor =
              score >= 80 ? "text-red-500" :
              score >= 50 ? "text-orange-500" :
              score >= 25 ? "text-yellow-500" :
              "text-emerald-500";
            const seqTier =
              score >= 80 ? "High Anomaly" :
              score >= 50 ? "Anomalous" :
              score >= 25 ? "Elevated" :
              "Normal";
            const seqTierClass =
              score >= 80 ? "text-red-400 border-red-500/30 bg-red-500/10" :
              score >= 50 ? "text-orange-400 border-orange-500/30 bg-orange-500/10" :
              score >= 25 ? "text-yellow-400 border-yellow-500/30 bg-yellow-500/10" :
              "text-emerald-400 border-emerald-500/30 bg-emerald-500/10";

            return (
              <Card className={seqBorderColor}>
                <CardHeader className="pb-3 border-b border-border/50">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Network className="h-5 w-5 text-muted-foreground" />
                      <CardTitle className="text-base">Sequence Anomaly Score</CardTitle>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-[10px] px-2 py-0 border border-emerald-500/30 text-emerald-400">
                        Reliable
                      </Badge>
                      <Badge variant="outline" className={cn("text-xs border px-2.5 py-0.5", seqTierClass)}>
                        {seqTier}
                      </Badge>
                    </div>
                  </div>
                  <CardDescription className="text-xs mt-1">
                    GRU next-event predictor scores how much the latest event deviates from learned sequence patterns.
                    Scores above 50 indicate unusual event ordering or feature combinations. Labels are never used.
                  </CardDescription>
                </CardHeader>
                <CardContent className="pt-4 space-y-3">
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-muted-foreground uppercase tracking-wider">Latest Score</span>
                      <span className={cn("font-mono font-bold text-sm", seqTextColor)}>
                        {score.toFixed(1)} / 100
                      </span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-muted/30 overflow-hidden">
                      <div
                        className={cn("h-full rounded-full transition-all", seqBarColor)}
                        style={{ width: `${Math.min(score, 100)}%` }}
                      />
                    </div>
                    <div className="flex justify-between mt-1 text-[10px] text-muted-foreground/60">
                      <span>Normal (&lt;25)</span><span>Elevated (25–50)</span><span>Anomalous (≥50)</span>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-4 text-xs text-muted-foreground pt-1">
                    <span>
                      Prediction error:{" "}
                      <span className="font-mono text-foreground/70">
                        {seqScore.prediction_error?.toFixed(5) ?? "—"}
                      </span>
                    </span>
                    <span>
                      History:{" "}
                      <span className="font-mono text-foreground/70">{seqScore.history_event_count} events</span>
                    </span>
                    {seqScore.model && (
                      <span>
                        Model:{" "}
                        <span className="font-mono text-foreground/70">
                          GRU hidden={seqScore.model.hidden_size} · label-free
                        </span>
                      </span>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })()}

          {/* ── ML Risk Summary ─────────────────────────────────────────────── */}
          {!loadingRisk && risk?.has_results && (risk.recent_anomalies?.length ?? 0) > 0 && (
            <Card className="border-orange-500/20">
              <CardHeader className="pb-3 bg-orange-500/5 border-b border-orange-500/10">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-5 w-5 text-orange-500" />
                  <CardTitle className="text-base text-orange-500">
                    Detected Anomalous Events
                  </CardTitle>
                </div>
                <CardDescription className="text-xs mt-1">
                  Events flagged by the Isolation Forest model based on behavioral deviation.
                  Reasons are derived from feature values — not from ground-truth labels.
                </CardDescription>
              </CardHeader>
              <div className="w-full overflow-auto">
                <table className="w-full text-sm text-left">
                  <thead className="text-xs text-muted-foreground bg-muted/20 uppercase font-mono tracking-wider border-b border-border/50">
                    <tr>
                      <th className="px-4 py-3 font-medium">Timestamp</th>
                      <th className="px-4 py-3 font-medium">Risk</th>
                      <th className="px-4 py-3 font-medium">Resource / Location</th>
                      <th className="px-4 py-3 font-medium">Behavioral Reasons</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/50 font-mono text-xs">
                    {risk.recent_anomalies!.map((ev: ScoredEvent) => (
                      <tr key={ev.event_id} className="hover:bg-muted/10 transition-colors">
                        <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">
                          {formatDate(ev.timestamp)}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-col gap-1">
                            <span className={cn("font-bold", scoreColor(ev.risk_score))}>
                              {ev.risk_score}
                            </span>
                            <Badge
                              variant="outline"
                              className={cn("text-[10px] px-1.5 py-0 border w-fit", riskBadgeClass(ev.risk_level))}
                            >
                              {ev.risk_level}
                            </Badge>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-col gap-0.5">
                            <span className="text-foreground max-w-[200px] truncate" title={ev.resource_accessed}>
                              {ev.resource_accessed}
                            </span>
                            <span className="text-muted-foreground text-[10px]">
                              {ev.source_ip} • {ev.geo_location}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3 max-w-[260px]">
                          <div className="flex flex-col gap-1">
                            {(ev.reasons ?? []).map((r, i) => (
                              <div key={i} className="flex items-center gap-1">
                                <AlertTriangle className="h-3 w-3 text-orange-500 shrink-0" />
                                <span className="text-muted-foreground">{r}</span>
                              </div>
                            ))}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {/* ── Event History ────────────────────────────────────────────────── */}
          <Card>
            <CardHeader className="pb-4">
              <CardTitle className="text-lg">Event History</CardTitle>
            </CardHeader>
            <div className="w-full overflow-auto border-t border-border/50">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-muted-foreground bg-muted/20 uppercase font-mono tracking-wider border-b border-border/50">
                  <tr>
                    <th className="px-4 py-3 font-medium">Timestamp</th>
                    <th className="px-4 py-3 font-medium">Label</th>
                    <th className="px-4 py-3 font-medium">Risk</th>
                    <th className="px-4 py-3 font-medium">Resource/IP</th>
                    <th className="px-4 py-3 font-medium">Auth</th>
                    <th className="px-4 py-3 font-medium text-right">Dur (s)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50 font-mono text-xs">
                  {data.events.length > 0 ? (
                    data.events.map((ev) => {
                      // Look up ML risk for this event from recent_anomalies
                      const evRisk = risk?.recent_anomalies?.find(
                        (r: ScoredEvent) => r.event_id === ev.event_id
                      );
                      return (
                        <tr key={ev.event_id} className={cn(
                          "hover:bg-muted/10 transition-colors",
                          evRisk ? "bg-orange-500/5" : ""
                        )}>
                          <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">
                            {formatDate(ev.timestamp)}
                          </td>
                          <td className="px-4 py-3">
                            <Badge
                              variant={getLabelColor(ev.label)}
                              className="rounded-sm px-1.5 py-0.5 text-[10px] font-mono font-medium"
                            >
                              {ev.label}
                            </Badge>
                          </td>
                          <td className="px-4 py-3">
                            {evRisk ? (
                              <span className={cn("font-bold", scoreColor(evRisk.risk_score))}>
                                {evRisk.risk_score}
                              </span>
                            ) : (
                              <span className="text-muted-foreground/40">—</span>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex flex-col gap-1">
                              <span
                                className="text-foreground max-w-[300px] truncate"
                                title={ev.resource_accessed}
                              >
                                {ev.resource_accessed}
                              </span>
                              <span className="text-muted-foreground text-[10px]">
                                {ev.source_ip} • {ev.geo_location}
                              </span>
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
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                        No events found for this identity.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      ) : (
        <div className="text-center py-20 text-destructive bg-destructive/10 border border-destructive/20 rounded-lg">
          Identity not found or failed to load.
        </div>
      )}
    </div>
  );
}
