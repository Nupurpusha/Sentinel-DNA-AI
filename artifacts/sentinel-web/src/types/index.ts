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
  history_event_count?: number;
  baseline_status?: 'Established' | 'Cold Start';
  minimum_history_events?: number;
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
  ml_score_norm?: number;
  behavioral_deviation_score?: number;
  evidence_count?: number;
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
  label_leakage_test_passed?: boolean;
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
  avg_behavioral_deviation?: number;
  avg_evidence_count?: number;
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

// ─── Step 3: SOC Alert Budget & Priority Alert types ──────────────────────────

export interface PriorityAlert {
  event_id: string;
  entity_id: string;
  entity_type: string;
  timestamp: string;
  risk_score: number;
  risk_level: 'Low' | 'Medium' | 'High' | 'Critical';
  ml_score_norm: number;
  behavioral_deviation_score: number;
  evidence_count: number;
  primary_reason: string;
  reasons: string[];
  resource_accessed: string;
  geo_location: string;
  label: string;
  // Step 6: Anomaly-type classification
  predicted_anomaly_type?: string | null;
  classification_confidence?: number | null;
  classification_reasons?: string[];
}

// ─── Step 6: Temporal Drift ───────────────────────────────────────────────────

export interface TemporalDrift {
  entity_id: string;
  baseline_status: 'Established' | 'Cold Start';
  history_event_count: number;
  minimum_history_events: number;
  temporal_drift_score: number;
  temporal_status: 'Stable' | 'Elevated' | 'High Drift';
  temporal_reasons: string[];
}

// ─── Step 6: Anomaly Classification Metrics ───────────────────────────────────

export interface PerTypeClassificationMetric {
  precision: number;
  recall: number;
  f1_score: number;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  support: number;
}

export interface ClassificationMetrics {
  has_results: boolean;
  total_anomalous_events?: number;
  overall_accuracy?: number;
  unknown_rate?: number;
  per_type?: Record<string, PerTypeClassificationMetric>;
  top1_pct_classification_accuracy?: number | null;
  classifier_leakage_test_passed?: boolean;
  note?: string;
}

export interface PriorityAlertsResponse {
  alerts: PriorityAlert[];
  total_events: number;
  alert_count: number;
  budget_pct: number;
}

export interface AlertBudgetRow {
  budget_pct: number;
  alert_count: number;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
}

export interface AlertBudgetResponse {
  has_results: boolean;
  total_events?: number;
  total_attacks?: number;
  budgets?: AlertBudgetRow[];
  note?: string;
}

export interface AttackCoverageRow {
  attack_type: string;
  total_gt: number;
  captured_top1: number;
  coverage_pct: number;
}

export interface AttackCoverageResponse {
  has_results: boolean;
  total_events?: number;
  alert_count?: number;
  budget_pct?: number;
  coverage?: AttackCoverageRow[];
  note?: string;
}

export interface Top1Metrics {
  has_results: boolean;
  alert_count?: number;
  total_events?: number;
  total_attacks?: number;
  true_positives?: number;
  false_positives?: number;
  precision?: number;
  recall?: number;
  f1_score?: number;
  note?: string;
}

// ─── GRU Sequence Detector ────────────────────────────────────────────────────

export interface SequenceRecentScore {
  event_id: string;
  timestamp: string;
  score: number;
  prediction_error: number;
}

export interface SequenceScore {
  entity_id: string;
  history_event_count: number;
  minimum_history_events: number;
  sequence_length: number;
  features: string[];
  score: number | null;
  prediction_error: number | null;
  reliable: boolean;
  status: string;
  message?: string;
  recent_scores: SequenceRecentScore[];
  model?: {
    type: string;
    hidden_size: number;
    training_windows: number;
    ground_truth_labels_used: boolean;
  };
}

export interface SequenceCoverageItem {
  attack_type: string;
  holdout_support: number;
  captured_at_threshold: number;
  coverage_pct: number;
}

export interface SequenceEvaluation {
  has_results: boolean;
  status: string;
  evaluation?: {
    split: string;
    train_fraction: number;
    identities_evaluated: number;
    train_events: number;
    holdout_events: number;
    holdout_attack_events: number;
    sequence_length: number;
    minimum_history_events: number;
    threshold: number;
  };
  metrics?: {
    roc_auc: number | null;
    average_precision: number | null;
    precision: number;
    recall: number;
    f1_score: number;
    predicted_anomalies: number;
  };
  attack_category_coverage?: SequenceCoverageItem[];
  label_leakage?: {
    sequence_scores_unchanged: boolean;
    existing_risk_ranking_unchanged: boolean;
    labels_used_for_training_or_scoring: boolean;
  };
  model?: {
    type: string;
    hidden_size: number;
    training_epochs: number;
    training_windows: number;
    random_seed: number;
  };
}
