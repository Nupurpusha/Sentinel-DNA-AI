import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Fingerprint,
  Globe2,
  Loader2,
  MapPin,
  Server,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import { PriorityAlert, EventRow, IdentityProfile } from "@/types";
import { Tag } from "lucide-react";
import { formatDate, cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export type AnalystDisposition = "Investigate" | "Escalate" | "Benign";

interface IdentityPayload {
  identity: {
    entity_id: string;
    entity_type: string;
    profile: IdentityProfile;
  };
  events: EventRow[];
  history_event_count?: number;
  baseline_status?: "Established" | "Cold Start";
  minimum_history_events?: number;
}

interface AlertInvestigationDialogProps {
  alert: PriorityAlert | null;
  disposition?: AnalystDisposition;
  onDispositionChange: (disposition: AnalystDisposition) => void;
  onClose: () => void;
}

interface Comparison {
  label: string;
  expected: string;
  observed: string;
  deviates: boolean;
}

function formatHour(hour: number) {
  return `${String(hour).padStart(2, "0")}:00`;
}

function formatHours(hours: number[]) {
  if (!hours.length) return "No baseline recorded";
  return `${formatHour(Math.min(...hours))}–${formatHour(Math.max(...hours))} UTC`;
}

function formatDuration(duration: number) {
  return `${duration.toLocaleString()} seconds`;
}

function riskBg(level: string) {
  switch (level) {
    case "Critical":
      return "bg-red-500/10 text-red-400 border-red-500/30";
    case "High":
      return "bg-orange-500/10 text-orange-400 border-orange-500/30";
    case "Medium":
      return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
    default:
      return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
  }
}

function entityIcon(type: string) {
  return type === "user" ? "User" : type === "service_account" ? "Service account" : "Edge device";
}

function comparisonRows(profile: IdentityProfile, event: EventRow): Comparison[] {
  const hour = new Date(event.timestamp).getHours();
  const sessionOutsideRange =
    event.session_duration < profile.session_dur_min ||
    event.session_duration > profile.session_dur_max;

  return [
    {
      label: "Location",
      expected: profile.primary_location,
      observed: event.geo_location,
      deviates: event.geo_location !== profile.primary_location,
    },
    {
      label: "Device",
      expected: profile.known_devices.length
        ? `${profile.known_devices.length} known device${profile.known_devices.length === 1 ? "" : "s"}`
        : "No known devices recorded",
      observed: event.device_fingerprint || "Unavailable",
      deviates: !profile.known_devices.includes(event.device_fingerprint ?? ""),
    },
    {
      label: "Access hour",
      expected: formatHours(profile.normal_hours),
      observed: `${formatHour(hour)} UTC`,
      deviates: !profile.normal_hours.includes(hour),
    },
    {
      label: "Resource",
      expected: profile.common_resources.length
        ? `${profile.common_resources.length} common resource${profile.common_resources.length === 1 ? "" : "s"}`
        : "No common resources recorded",
      observed: event.resource_accessed,
      deviates: !profile.common_resources.includes(event.resource_accessed),
    },
    {
      label: "Authentication",
      expected: `${profile.preferred_auth} · successful`,
      observed: `${event.auth_method} · ${event.auth_success ? "successful" : "failed"}`,
      deviates: event.auth_method !== profile.preferred_auth || !event.auth_success,
    },
    {
      label: "Session duration",
      expected: `${formatDuration(profile.session_dur_min)}–${formatDuration(profile.session_dur_max)}`,
      observed: formatDuration(event.session_duration),
      deviates: sessionOutsideRange,
    },
  ];
}

export function AlertInvestigationDialog({
  alert,
  disposition,
  onDispositionChange,
  onClose,
}: AlertInvestigationDialogProps) {
  const [event, setEvent] = useState<EventRow | null>(null);
  const [profile, setProfile] = useState<IdentityProfile | null>(null);
  const [baselineStatus, setBaselineStatus] = useState<"Established" | "Cold Start" | null>(null);
  const [historyEventCount, setHistoryEventCount] = useState<number | null>(null);
  const [minimumHistoryEvents, setMinimumHistoryEvents] = useState(50);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!alert) {
      setEvent(null);
      setProfile(null);
      setBaselineStatus(null);
      setHistoryEventCount(null);
      setMinimumHistoryEvents(50);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setEvent(null);
    setProfile(null);
    setBaselineStatus(null);
    setHistoryEventCount(null);
    setMinimumHistoryEvents(50);

    fetch(`/sentinel-api/identities/${alert.entity_id}`)
      .then((response) => {
        if (!response.ok) throw new Error("Unable to load identity telemetry");
        return response.json() as Promise<IdentityPayload>;
      })
      .then((payload) => {
        if (cancelled) return;
        setProfile(payload.identity.profile);
        setEvent(payload.events.find((candidate) => candidate.event_id === alert.event_id) ?? null);
        const count = payload.history_event_count ?? payload.events.length;
        setBaselineStatus(
          payload.baseline_status ?? (count >= (payload.minimum_history_events ?? 50) ? "Established" : "Cold Start"),
        );
        setHistoryEventCount(count);
        setMinimumHistoryEvents(payload.minimum_history_events ?? 50);
      })
      .catch((error) => {
        if (!cancelled) console.error(error);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [alert]);

  const comparisons = useMemo(
    () => (profile && event ? comparisonRows(profile, event) : []),
    [profile, event],
  );
  const baselineEstablished = baselineStatus === "Established";
  const deviations = baselineEstablished
    ? comparisons.filter((comparison) => comparison.deviates)
    : [];
  const reasons = alert?.reasons ?? [];

  return (
    <Dialog open={alert !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[92vh] max-w-5xl overflow-y-auto border-border/70 bg-background p-0">
        {alert && (
          <>
            <DialogHeader className="border-b border-border/60 bg-muted/15 px-6 py-5">
              <div className="flex flex-wrap items-start justify-between gap-3 pr-6">
                <div>
                  <div className="mb-2 flex items-center gap-2">
                    <ShieldAlert className="h-5 w-5 text-red-500" />
                    <Badge variant="outline" className={cn("text-[10px] uppercase", riskBg(alert.risk_level))}>
                      {alert.risk_level} priority alert
                    </Badge>
                  </div>
                  <DialogTitle className="font-mono text-xl">{alert.entity_id}</DialogTitle>
                  <DialogDescription className="mt-1">
                    Analyst investigation view · existing telemetry and behavioral evidence
                  </DialogDescription>
                </div>
                <div className="text-right">
                  <div className="font-mono text-3xl font-bold text-red-400">{alert.risk_score}</div>
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Final risk score</div>
                </div>
              </div>
            </DialogHeader>

            <div className="space-y-5 px-6 py-5">
              <section>
                <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Alert details
                </h3>
                <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                  <Detail label="Entity type" value={entityIcon(alert.entity_type)} />
                  <Detail label="Timestamp" value={formatDate(alert.timestamp)} />
                  <Detail label="ML anomaly score" value={`${alert.ml_score_norm} / 100`} />
                  <Detail label="Behavioral deviation" value={`${alert.behavioral_deviation_score} / 100`} />
                  <Detail label="Evidence count" value={`${alert.evidence_count} signals`} />
                  <Detail label="Resource" value={event?.resource_accessed ?? alert.resource_accessed} mono />
                  <Detail label="Location" value={event?.geo_location ?? alert.geo_location} />
                  <Detail label="Device" value={event?.device_fingerprint ?? "Loading telemetry…"} mono />
                  <Detail
                    label="Authentication"
                    value={
                      event
                        ? `${event.auth_method} · ${event.auth_success ? "Success" : "Failed"}`
                        : "Loading telemetry…"
                    }
                  />
                </div>
              </section>

              <section className="rounded-lg border border-red-500/20 bg-red-500/5 p-4">
                <div className="mb-3 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-orange-400" />
                  <h3 className="text-sm font-semibold text-orange-300">Why SentinelDNA Flagged This</h3>
                </div>
                {reasons.length > 0 ? (
                  <ul className="grid gap-2 md:grid-cols-2">
                    {reasons.map((reason) => (
                      <li key={reason} className="flex items-start gap-2 text-sm text-foreground/85">
                        <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-orange-400" />
                        {reason}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-muted-foreground">No behavioral explanation was recorded for this alert.</p>
                )}
              </section>

              {/* ── Step 6: Anomaly-Type Classification ───────────────────────── */}
              {alert.predicted_anomaly_type && alert.predicted_anomaly_type !== "normal_activity" && (
                <section className="rounded-lg border border-violet-500/25 bg-violet-500/5 p-4">
                  <div className="mb-3 flex items-center gap-2">
                    <Tag className="h-4 w-4 text-violet-400" />
                    <h3 className="text-sm font-semibold text-violet-300">Predicted Anomaly Type</h3>
                  </div>
                  <div className="flex flex-wrap items-center gap-3 mb-3">
                    <span className="rounded-md border border-violet-500/40 bg-violet-500/10 px-3 py-1.5 font-mono text-sm font-semibold text-violet-300">
                      {alert.predicted_anomaly_type}
                    </span>
                    {alert.classification_confidence != null && (
                      <span className="text-xs text-muted-foreground">
                        Confidence:{" "}
                        <span className={cn(
                          "font-mono font-semibold",
                          alert.classification_confidence >= 0.7 ? "text-emerald-400" :
                          alert.classification_confidence >= 0.4 ? "text-yellow-400" : "text-orange-400"
                        )}>
                          {(alert.classification_confidence * 100).toFixed(0)}%
                        </span>
                      </span>
                    )}
                    <span className="text-[10px] text-muted-foreground/60 italic">
                      Rule-based — labels never used as input
                    </span>
                  </div>
                  {(alert.classification_reasons ?? []).length > 0 && (
                    <ul className="grid gap-1.5 md:grid-cols-2">
                      {(alert.classification_reasons ?? []).map((reason) => (
                        <li key={reason} className="flex items-start gap-2 text-xs text-foreground/80">
                          <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-violet-400" />
                          {reason}
                        </li>
                      ))}
                    </ul>
                  )}
                </section>
              )}

              <section>
                <div className="mb-3 flex items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-semibold">Behavioral DNA comparison</h3>
                    <p className="text-xs text-muted-foreground">Expected baseline vs observed alert telemetry</p>
                  </div>
                  {event && (
                    <Badge variant="outline" className="text-[10px]">
                      {baselineEstablished
                        ? `${deviations.length} genuine deviation${deviations.length === 1 ? "" : "s"}`
                        : "Baseline not established"}
                    </Badge>
                  )}
                </div>

                {baselineStatus === "Cold Start" && (
                  <div className="mb-3 rounded-lg border border-yellow-500/30 bg-yellow-500/5 px-4 py-3 text-xs text-yellow-200">
                    <strong>Cold Start:</strong> only {historyEventCount ?? 0} historical events are available.
                    Expected vs Observed values are shown for context, but deviations are not considered reliable
                    until {minimumHistoryEvents} events are available.
                  </div>
                )}

                {loading ? (
                  <div className="flex items-center justify-center rounded-lg border border-border/60 py-10 text-sm text-muted-foreground">
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Loading identity baseline and event telemetry…
                  </div>
                ) : event && profile ? (
                  <div className="overflow-hidden rounded-lg border border-border/60">
                    <div className="grid grid-cols-[1fr_1.2fr_1.2fr] border-b border-border/60 bg-muted/20 px-4 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                      <span>Signal</span>
                      <span>Expected behavior</span>
                      <span>Observed behavior</span>
                    </div>
                    <div className="divide-y divide-border/50">
                      {comparisons.map((comparison) => (
                        <div
                          key={comparison.label}
                          className={cn(
                            "grid grid-cols-[1fr_1.2fr_1.2fr] px-4 py-3 text-xs",
                            baselineEstablished && comparison.deviates && "bg-orange-500/5",
                          )}
                        >
                          <span className="font-medium text-foreground">{comparison.label}</span>
                          <span className="text-muted-foreground">{comparison.expected}</span>
                          <span className={cn(
                            baselineEstablished && comparison.deviates
                              ? "font-medium text-orange-300"
                              : "text-foreground/80",
                          )}>
                            {baselineEstablished && comparison.deviates && <AlertTriangle className="mr-1 inline h-3 w-3" />}
                            {comparison.observed}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="rounded-lg border border-border/60 px-4 py-8 text-center text-sm text-muted-foreground">
                    The selected event telemetry could not be loaded.
                  </div>
                )}
              </section>

              <section className="border-t border-border/60 pt-4">
                <div className="mb-3">
                  <h3 className="text-sm font-semibold">Analyst disposition</h3>
                  <p className="text-xs text-muted-foreground">
                    Demo-only local action. This selection does not retrain the model or change alert ranking.
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {(["Investigate", "Escalate", "Benign"] as AnalystDisposition[]).map((option) => (
                    <Button
                      key={option}
                      type="button"
                      variant={disposition === option ? "default" : "outline"}
                      className={cn(
                        "gap-2",
                        disposition === option && option === "Escalate" && "bg-red-600 hover:bg-red-700",
                        disposition === option && option === "Benign" && "bg-emerald-600 hover:bg-emerald-700",
                      )}
                      onClick={() => onDispositionChange(option)}
                    >
                      {option === "Investigate" && <Clock3 className="h-4 w-4" />}
                      {option === "Escalate" && <ShieldAlert className="h-4 w-4" />}
                      {option === "Benign" && <CheckCircle2 className="h-4 w-4" />}
                      {option}
                    </Button>
                  ))}
                  {disposition && (
                    <span className="self-center text-xs text-muted-foreground">
                      Marked <span className="font-medium text-foreground">{disposition}</span> for this demo session.
                    </span>
                  )}
                </div>
              </section>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-md border border-border/50 bg-muted/10 px-3 py-2.5">
      <div className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={cn("truncate text-sm text-foreground", mono && "font-mono")} title={value}>
        {value}
      </div>
    </div>
  );
}