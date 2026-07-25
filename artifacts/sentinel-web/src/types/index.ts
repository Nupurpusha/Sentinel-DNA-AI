export interface Summary {
  total_events: number;
  total_identities: number;
  normal_count: number;
  anomaly_count: number;
  normal_pct: number;
  anomaly_pct: number;
  by_label: Record<string, number>;
  by_entity_type: Record<string, number>;
  by_department: Record<string, number>;
}

export interface EventRow {
  event_id: string;
  entity_id: string;
  entity_type: string;
  timestamp: string;
  source_ip: string;
  geo_location: string;
  latitude?: number;
  longitude?: number;
  resource_accessed: string;
  auth_method: string;
  auth_success: boolean;
  session_duration: number;
  command_sequence?: string[];
  device_fingerprint?: string;
  department: string;
  label: string;
}

export interface EventsResponse {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  events: EventRow[];
}

export interface IdentityProfile {
  normal_hours: number[];
  primary_location: string;
  primary_lat?: number;
  primary_lng?: number;
  known_devices: string[];
  common_resources: string[];
  preferred_auth: string;
  session_dur_min: number;
  session_dur_max: number;
  ip_prefix?: string;
  typical_commands?: string[];
}

export interface Identity {
  entity_id: string;
  entity_type: string;
  department: string;
  profile: IdentityProfile;
  created_at: string;
}

export interface IdentityResponse {
  identity: Identity;
  event_count: number;
  events: EventRow[];
}

export interface IdentityListItem {
  entity_id: string;
  entity_type: string;
  department: string;
  created_at: string;
}

export interface IdentitiesResponse {
  identities: IdentityListItem[];
}

// ─── Step 2: Detection types ──────────────────────────────────────────────────

export interface ScoredEvent {
  event_id: string;
  entity_id: string;
  entity_type: string;
  department: string;
  timestamp: string;
  source_ip: string;
  geo_location: string;
  resource_accessed: string;
  auth_method: string;
  auth_success: boolean;
  session_duration: number;
  device_fingerprint: string;
  label: string;
  // ML fields
  anomaly_score: number;
  risk_score: number;
  predicted_anomaly: number;
  risk_level: 'Low' | 'Medium' | 'High' | 'Critical';
  reasons: string[];
}

export interface ScoredEventsResponse {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  events: ScoredEvent[];
}

export interface HighRiskEventsResponse {
  events: ScoredEvent[];
}

export interface DetectionSummary {
  has_results: boolean;
  total_scored?: number;
  detected_anomalies?: number;
  high_critical_count?: number;
  avg_risk_score?: number;
  by_risk_level?: Record<string, number>;
}

export interface DetectionStatus {
  has_results: boolean;
  scored_events: number;
}

export interface RiskTrendDay {
  day: string;
  total_events: number;
  anomalies: number;
  avg_risk_score: number;
}

export interface RiskTrendResponse {
  trend: RiskTrendDay[];
}

export interface TopIdentity {
  entity_id: string;
  entity_type: string;
  department: string;
  avg_risk_score: number;
  max_risk_score: number;
  detected_anomalies: number;
  total_events: number;
  max_risk_level: string;
}

export interface TopIdentitiesResponse {
  identities: TopIdentity[];
}

export interface IdentityRisk {
  has_results: boolean;
  entity_id: string;
  avg_risk_score?: number;
  max_risk_score?: number;
  risk_level?: string;
  detected_anomalies?: number;
  total_events?: number;
  recent_anomalies?: ScoredEvent[];
}

export interface ModelMetrics {
  has_results: boolean;
  precision?: number;
  recall?: number;
  f1_score?: number;
  true_positives?: number;
  false_positives?: number;
  false_negatives?: number;
  true_negatives?: number;
  roc_auc?: number | null;
  total_true_anomalies?: number;
  total_predicted_anomalies?: number;
  note?: string;
}
