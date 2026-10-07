export {
  ALGORITHM_SCHEMA_VERSION,
  ALGORITHM_FAMILIES,
  ALGORITHM_MAX_CANDIDATES,
  ALGORITHM_MAX_CANDIDATE_LABEL_CHARS,
  ALGORITHM_MAX_DECISION_CHARS,
  ALGORITHM_MAX_REASONING_SUMMARY_CHARS,
  ALGORITHM_MAX_OIDATA_ITERATIONS,
  ALGORITHM_MIN_BUDGET_WEIGHT,
  ALGORITHM_MAX_BUDGET_WEIGHT,
  KNOWN_ALGORITHM_INPUT_SENSITIVITIES,
  KNOWN_GOAL_PRIORITY_HINTS,
  KNOWN_RISK_VERDICT_TIERS,
  OIDATA_PHASES,
  isAlgorithmFamily,
  isAlgorithmInputSensitivity,
  isAlgorithmDenial,
  isOidaPhase,
  isGoalPriorityHint,
  isRiskVerdictTier,
  type AlgorithmSchemaVersion,
  type AlgorithmFamily,
  type AlgorithmInputSensitivity,
  type AlgorithmDecisionInput,
  type AlgorithmRecommendation,
  type AlgorithmDenyReason,
  type AlgorithmDenial,
  type AlgorithmEvaluationSuccess,
  type AlgorithmEvaluationResult,
  type AlgorithmSelectionResult,
  type RuntimeContext,
  type AlgorithmStrategy,
  type StrategyContract,
  type StrategyDescriptor,
  type OidaPhase,
  type OidaLoopState,
  type OidaStateValidation,
  type OidaAdvanceResult,
  type GoalPriorityHint,
  type AlgorithmBudget,
  type GoalScoreRecord,
  type RiskVerdictTier,
  type RiskVerdict,
  type MemoryRetrievalPort,
  type MemoryProjectionResult,
} from "./types.js";
export { RetrievalPortError } from "./types.js";

export {
  StrategyRegistry,
  canonicalSerializeStrategy,
  canonicalStrategyHash,
} from "./registry.js";

export {
  serializeRecommendation,
  recommendationHash,
  serializeAlgorithmResult,
} from "./serialize.js";

export {
  StrategySelector,
  validateDecisionInput,
  type AlgorithmLedgerEmitter,
  type StrategySelectorOptions,
} from "./selector.js";

export {
  TEN_ALGORITHM_FAMILIES,
  FAMILY_CONTRACTS,
  CONTRACT_ONLY_PLACEHOLDERS,
  REFERENCE_STRATEGIES,
  oidaLoopLite,
  runtimeRiskLabelRank,
  selfMonitoringOutcomeRecord,
  buildDefaultStrategyRegistry,
  validateRegistryCompleteness,
  familyContract,
  type FamilyContract,
} from "./families.js";

// Phase 17D — bounded self-monitoring & adaptation surface.
export {
  AdaptiveParameterStore,
  buildSelfMonitoringStrategy,
  selfMonitoringMetricObserve,
  globalDefaultStore,
  DEFAULT_TUNABLE_PARAMETERS,
  deriveAdaptationProposal,
  executionStatsFeedbackPort,
  validateMetricsInput,
  METRIC_DENY_RATIO,
  METRIC_FAILURE_RATIO,
  METRIC_SUCCESS_RATIO,
  type ParameterChangeRecord,
  type AdaptiveParameterStoreOptions,
} from "./selfMonitoring.js";
export {
  ALGORITHM_MAX_METRICS,
  ALGORITHM_MAX_METRIC_NAME_CHARS,
  ALGORITHM_MAX_PARAMETER_MAGNITUDE,
  ALGORITHM_MAX_TUNABLE_PARAMETERS,
  ALGORITHM_MAX_PARAMETER_HISTORY,
} from "./types.js";
export type {
  MetricFeedbackPort,
  MonitorMetric,
  ParameterBounds,
  ParameterSensitivity,
  TunableParameterState,
  AdaptationProposal,
} from "./types.js";

// Phase 17B — OIDA state machine + Goal Priority surface.
export {
  initialOidaState,
  validateOidaState,
  advanceOida,
  completeOidaLoop,
} from "./oida.js";
export { oidaLoopLite as oidaLoopLiteStrategy, OidaStateError } from "./oidaStrategy.js";
export {
  goalPriorityHintBudget,
  GOAL_PRIORITY_HINT_WEIGHTS,
  GOAL_URGENCY_PREFIX_WEIGHTS,
  rankGoalsDeterministic,
  validateGoalPriorityInput,
  goalUrgencyWeight,
} from "./goalPriority.js";

// Phase 17C — integration surface (memory port, risk verdicts, capability
// filtering) + upgraded risk/skill strategies + port-bound retrieval strategy.
export {
  memoryRetrievalPortAdapter,
  projectHitsToLabels,
  applyRiskVerdict,
  filterSkillsByCapabilities,
  validateGrantedCapabilities,
  ALGORITHM_MAX_MEMORY_HITS,
  ALGORITHM_MAX_SNIPPET_CHARS,
  type SkillFilterResult,
} from "./integration.js";
export {
  runtimeRiskGateRank,
  skillCapabilityMapLite,
} from "./riskSkill.js";
export {
  buildContextMemoryStrategy,
  CONTEXT_MEMORY_STRATEGY_ID,
} from "./contextMemory.js";
