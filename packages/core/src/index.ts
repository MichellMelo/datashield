export type DocumentFormat = "PDF" | "DOCX" | "CSV";

export type ExportFormat = "PDF" | "DOCX" | "CSV" | "TXT" | "JSON";

export type SanitizationAction =
  | "REDACT"
  | "PSEUDONYMIZE"
  | "GENERALIZE"
  | "KEEP"
  | "MANUAL_REVIEW";

export type SensitiveEntityType =
  | "PERSON"
  | "CPF"
  | "RG"
  | "CNPJ"
  | "PHONE"
  | "EMAIL"
  | "ADDRESS"
  | "GPS"
  | "VEHICLE_PLATE"
  | "VEHICLE_CHASSIS"
  | "PROCESS_NUMBER"
  | "ORGANIZATION"
  | "ALIAS"
  | "SOURCE"
  | "OPERATIONAL_DATA";

export interface DocumentSection {
  id: string;
  type: "TEXT" | "TABLE";
  content: string;
  page?: number;
  row?: number;
}

export interface ExtractedDocument {
  id: string;
  format: DocumentFormat;
  sections: DocumentSection[];
}

export interface DetectedEntity {
  id: string;
  type: SensitiveEntityType;
  start: number;
  end: number;
  confidence: number;
  suggestedAction: SanitizationAction;
  reviewed: boolean;
}

export interface SanitizationPolicy {
  id: string;
  name: string;
  rules: Array<{
    entityType: SensitiveEntityType;
    action: SanitizationAction;
    enabled: boolean;
  }>;
  requireManualReview: boolean;
  blockOnUnresolvedEntities: boolean;
}

export interface ValidationResult {
  approved: boolean;
  unresolvedEntities: number;
  criticalFindings: number;
  warnings: string[];
}
