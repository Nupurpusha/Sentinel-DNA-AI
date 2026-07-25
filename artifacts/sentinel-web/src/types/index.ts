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
