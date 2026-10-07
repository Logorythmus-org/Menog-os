export {
  SEMANTIQ_SCHEMA_VERSION,
  SEMANTIQ_STAGES,
  KNOWN_SEMANTIQ_EVENT_TYPES,
  KNOWN_SEMANTIQ_TRIGGERS,
  KNOWN_SEMANTIQ_CLAIM_KINDS,
  KNOWN_SEMANTIQ_DENY_REASONS,
  type SemantiqSchemaVersion,
  type SemantiqEventType,
  type SemantiqStage,
  type SemantiqTrigger,
  type SemantiqClaimKind,
  type SemantiqDenyReason,
  type SemantiqAuthority,
  type SemantiqAdapterState,
  type SemantiqEventView,
  type SemantiqLedgerPort,
  type SemantiqLedgerEmitter,
  type SemantiqEvaluationRequest,
  type SemantiqClaim,
  type SemantiqEvaluation,
  type SemantiqDenial,
  type SemantiqResult,
  type SemantiqAdapterContract,
  type SemantiqRuntimeContext,
  type SemantiqEngine,
  type SemantiqLifecycleRecord,
} from "./types.js";

export {
  isSemantiqDenyReason,
  validateEvaluationRequest,
  normalizeClaim,
  normalizeEventView,
  SEMANTIQ_MAX_SUBJECT_CHARS,
  SEMANTIQ_MAX_NOTE_CHARS,
  SEMANTIQ_MAX_SUMMARY_CHARS,
  SEMANTIQ_MAX_CLAIMS,
  SEMANTIQ_MAX_CLAIM_VALUE_CHARS,
  SEMANTIQ_MAX_DERIVED_FROM,
  SEMANTIQ_MAX_EVENTS_PER_EVALUATION,
  SEMANTIQ_MAX_EVENT_ID_CHARS,
  SEMANTIQ_MAX_EVENT_TYPE_CHARS,
} from "./rules.js";

export {
  denyByDefaultSemantiqEmitter,
  buildDisabledAdapterState,
  buildSemantiqAdapter,
  type SemantiqContractOptions,
} from "./adapter.js";

// ---------------------------------------------------------------------------
// Phase 18B — Evaluation Event Model.
// ---------------------------------------------------------------------------
export type {
  SemantiqEvaluationDimension,
  SemantiqProvenanceSource,
  SemantiqDimensionScore,
  SemantiqEvaluationProvenance,
  SemantiqEvaluationEventKind,
  SemantiqEvaluationVerdict,
  SemantiqEvaluationRequestEvent,
  SemantiqEvaluationResultEvent,
  SemantiqEvaluationDeniedEvent,
  SemantiqEvaluationEvent,
  SemantiqEvaluationRecord,
} from "./types.js";
export {
  SEMANTIQ_EVALUATION_DIMENSIONS,
  SEMANTIQ_PROVENANCE_SOURCES,
  SEMANTIQ_EVALUATION_VERDICTS,
  isSemantiqEvaluationDimension,
} from "./types.js";

export {
  SEMANTIQ_MAX_EVENT_DIMENSIONS,
  SEMANTIQ_MAX_RECORDS,
  SEMANTIQ_MAX_ID_CHARS,
  SEMANTIQ_MAX_RATIONALE_CHARS,
  SEMANTIQ_MAX_PROVENANCE_NOTE_CHARS,
  SEMANTIQ_SCORE_STEP,
  SEMANTIQ_VERDICT_PASS_THRESHOLD,
  SEMANTIQ_VERDICT_BORDERLINE_THRESHOLD,
  isSemantiqProvenanceSource,
  isSemantiqVerdict,
  isSemantiqTrigger,
  snapScore,
  validateProvenance,
  validateDimensionScore,
  validateEvaluationEvent,
  deriveVerdict,
  detectScoreConflicts,
  serializeEvaluationEvent,
  evaluationEventHash,
  buildEvaluationRequestEvent,
  buildEvaluationResultEvent,
  buildEvaluationDeniedEvent,
  evaluationRecordId,
  type ScoreConflict,
  type EvaluationEventBuildInput,
  type EvaluationResultBuildInput,
  type EvaluationDeniedBuildInput,
} from "./events.js";

export {
  SemantiqEvaluationRecordStore,
  isCurrentSchemaVersion,
  type SemantiqStoreResult,
} from "./records.js";

export {
  requestEvaluation,
  contractLayerProvenance,
  SEMANTIQ_MAX_CONFLICTING_ENGINES,
  type RequestEvaluationInput,
  type EngineContribution,
  type RequestEvaluationOutcome,
} from "./requestFlow.js";

// ---------------------------------------------------------------------------
// Phase 18C — Evidence Export / Import.
// ---------------------------------------------------------------------------
export {
  SEMANTIQ_MAX_EXPORT_RECORDS,
  SEMANTIQ_MAX_EXPORT_EVENTS,
  SEMANTIQ_MAX_STRING_CHARS,
  SEMANTIQ_MAX_VALUE_CHARS,
  SEMANTIQ_MAX_TOTAL_BYTES,
  SEMANTIQ_SECRET_PATTERNS,
  redactValue,
  isSemantiqTransferDenyReason,
  KNOWN_SEMANTIQ_TRANSFER_DENY_REASONS,
  exportEvidence,
  importEvidence,
  type SemantiqTransferDenyReason,
  type RedactionResult,
  type SemantiqEvidenceEventSummary,
  type SemantiqEvidencePackageMetadata,
  type SemantiqEvidencePackage,
  type EvidenceExportInput,
  type EvidenceExportResult,
  type EvidenceImportOptions,
  type EvidenceImportResult,
} from "./transfer.js";

// ---------------------------------------------------------------------------
// Phase 18D — Evaluation Boundary Security.
// ---------------------------------------------------------------------------
export {
  SEMANTIQ_MAX_REJECTIONS,
  SEMANTIQ_HOSTILE_TEXT_PATTERNS,
  KNOWN_SEMANTIQ_HOSTILE_PATTERNS,
  KNOWN_SEMANTIQ_BOUNDARY_DENY_REASONS,
  isSemantiqBoundaryDenyReason,
  scanHostileText,
  inspectPayload,
  inspectScore,
  screenEvaluationRequest,
  buildRejectedInstruction,
  SemantiqRejectionLog,
  rejectionLedgerEmitter,
  type SemantiqHostilePattern,
  type SemantiqBoundaryDenyReason,
  type SemantiqFinding,
  type SemantiqScoreCheckInput,
  type SemantiqRejectedBy,
  type SemantiqRejectedInstruction,
  type RejectedInstructionInput,
  type ScreenResult,
} from "./boundary.js";
