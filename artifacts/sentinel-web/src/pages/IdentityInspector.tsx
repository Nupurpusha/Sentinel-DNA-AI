import { useState, useEffect } from "react";
import { useParams, useLocation } from "wouter";
import { IdentityResponse, IdentitiesResponse } from "@/types";
import { formatNumber, formatDate, cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { User, Server, MapPin, Clock, Fingerprint, Lock, CheckCircle2, XCircle } from "lucide-react";

export function IdentityInspector() {
  const { entityId } = useParams();
  const [, setLocation] = useLocation();

  const [identities, setIdentities] = useState<IdentitiesResponse | null>(null);
  const [loadingList, setLoadingList] = useState(true);

  const [data, setData] = useState<IdentityResponse | null>(null);
  const [loadingData, setLoadingData] = useState(false);

  useEffect(() => {
    const fetchIdentities = async () => {
      setLoadingList(true);
      try {
        const res = await fetch("/sentinel-api/identities");
        if (res.ok) {
          const json = await res.json();
          setIdentities(json);
          // If we don't have an entityId selected and there are identities, select the first one
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
        if (res.ok) {
          setData(await res.json());
        } else {
          setData(null);
        }
      } catch (err) {
        console.error(err);
        setData(null);
      } finally {
        setLoadingData(false);
      }
    };
    fetchIdentityData();
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
                  <div className="flex items-center justify-between w-full">
                    <span className="font-mono text-xs">{id.entity_id}</span>
                  </div>
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
          <div className="h-64 bg-muted/50 rounded-lg border border-border/50"></div>
          <div className="h-96 bg-muted/50 rounded-lg border border-border/50"></div>
        </div>
      ) : data ? (
        <div className="space-y-6">
          <Card className="border-primary/20 shadow-lg shadow-primary/5">
            <CardHeader className="bg-muted/10 border-b border-border/50 pb-6">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-4">
                  <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center border border-primary/20 text-primary">
                    {data.identity.entity_type === 'user' ? <User className="h-6 w-6" /> : <Server className="h-6 w-6" />}
                  </div>
                  <div>
                    <CardTitle className="text-2xl font-mono text-primary">{data.identity.entity_id}</CardTitle>
                    <CardDescription className="uppercase tracking-widest text-xs mt-1 font-semibold flex items-center gap-2">
                      <span>{data.identity.entity_type.replace('_', ' ')}</span>
                      <span className="w-1 h-1 rounded-full bg-muted-foreground"></span>
                      <span>{data.identity.department}</span>
                    </CardDescription>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-sm text-muted-foreground">Baseline Events</p>
                  <p className="text-2xl font-mono font-bold">{formatNumber(data.event_count)}</p>
                </div>
              </div>
            </CardHeader>
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
                      {data.identity.profile.known_devices.map(dev => (
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
                      Avg Session: {data.identity.profile.session_dur_min}s - {data.identity.profile.session_dur_max}s
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
                      {data.identity.profile.common_resources.map(res => (
                        <li key={res} className="text-xs text-muted-foreground font-mono truncate max-w-[200px]" title={res}>
                          {res}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

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
                    <th className="px-4 py-3 font-medium">Resource/IP</th>
                    <th className="px-4 py-3 font-medium">Auth</th>
                    <th className="px-4 py-3 font-medium text-right">Dur (s)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50 font-mono text-xs">
                  {data.events.length > 0 ? (
                    data.events.map((ev) => (
                      <tr key={ev.event_id} className="hover:bg-muted/10 transition-colors">
                        <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">{formatDate(ev.timestamp)}</td>
                        <td className="px-4 py-3">
                          <Badge variant={getLabelColor(ev.label)} className="rounded-sm px-1.5 py-0.5 text-[10px] font-mono font-medium">
                            {ev.label}
                          </Badge>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-col gap-1">
                            <span className="text-foreground max-w-[300px] truncate" title={ev.resource_accessed}>{ev.resource_accessed}</span>
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
                      <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">No events found for this identity.</td>
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
