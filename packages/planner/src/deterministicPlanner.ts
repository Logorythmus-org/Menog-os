import type {
  Goal,
  GoalBudget,
  PlanStep,
  Plan,
  PlannerDisposition,
  PlannerProposal,
  SideEffectClassUpperBound,
  PlanGraph,
} from "@menog/core";
import {
  maxSideEffectClass,
  isSideEffectClassUpperBound,
} from "@menog/core";
import type { VerbRegistry, VerbContract } from "@menog/verbs";
import {
  type CapabilityId,
  CAPABILITY_EFFECT_TABLE,
  requiresHumanApprovalFor,
} from "@menog/policy";
import type { SideEffectClass } from "@menog/shared";
import { isSideEffectClass } from "@menog/shared";
import {
  buildPlanGraph,
  type BuildPlanGraphOptions,
} from "./planGraphBuilder.js";

const PLANNER_SCHEMA_VERSION = "menog-planner/v0";

export interface DeterministicPlannerOptions {
  readonly unsupportedCapabilityDeny?: boolean;
  readonly emitObservabilityEvents?: boolean;
}

export interface PlannerObservationEvent {
  readonly schemaVersion: typeof PLANNER_SCHEMA_VERSION;
  readonly observationType:
    | "planner:goal_received"
    | "planner:step_validated"
    | "planner:step_rejected"
    | "planner:plan_proposed"
    | "planner:plan_rejected";
  readonly at: string;
  readonly goalId: string;
  readonly planId?: string;
  readonly stepIndex?: number;
  readonly verbId?: string;
  readonly requiredCapabilities?: readonly string[];
  readonly sideEffectClass?: SideEffectClass;
  readonly reason?: string;
  readonly trace: readonly string[];
}

export class DeterministicPlanner {
  readonly #registry: VerbRegistry;
  readonly #options: Required<DeterministicPlannerOptions>;
  readonly #observations: PlannerObservationEvent[] = [];

  constructor(
    registry: VerbRegistry,
    options: DeterministicPlannerOptions = {}
  ) {
    this.#registry = registry;
    this.#options = {
      unsupportedCapabilityDeny:
        typeof options.unsupportedCapabilityDeny === "boolean"
          ? options.unsupportedCapabilityDeny
          : true,
      emitObservabilityEvents:
        typeof options.emitObservabilityEvents === "boolean"
          ? options.emitObservabilityEvents
          : true,
    };
  }

  get registry(): VerbRegistry {
    return this.#registry;
  }

  observations(): readonly PlannerObservationEvent[] {
    return Object.freeze([...this.#observations]);
  }

  clearObservations(): void {
    this.#observations.length = 0;
  }

  propose(goal: Goal): PlannerProposal {
    const trace: string[] = [];
    const startAt = this.#isoTimestamp();

    this.#emitObs({
      observationType: "planner:goal_received",
      at: startAt,
      goalId: goal.goalId,
      trace: ["registryFingerprint:" + this.#registry.deterministicFingerprint().slice(0, 64)],
    });

    if (!goal || typeof goal !== "object") {
      trace.push("goal_must_be_object");
      return this.#rejectEmpty("empty_sequence_rejected", "goal must be an object", trace);
    }
    if (typeof goal.goalId !== "string" || goal.goalId.length === 0) {
      trace.push("goalId_required");
      return this.#rejectEmpty("empty_sequence_rejected", "goal.goalId must be a non-empty string", trace);
    }
    if (typeof goal.description !== "string" || goal.description.length === 0) {
      trace.push("description_required");
      return this.#rejectEmpty("empty_sequence_rejected", "goal.description must be a non-empty string", trace);
    }
    if (!Array.isArray(goal.requestedVerbSequence)) {
      trace.push("requestedVerbSequence_must_be_array");
      return this.#rejectEmpty("empty_sequence_rejected", "goal.requestedVerbSequence must be an array", trace);
    }
    if (goal.requestedVerbSequence.length === 0) {
      trace.push("empty_sequence");
      return this.#rejectEmpty("empty_sequence_rejected", "goal.requestedVerbSequence is empty; nothing to plan", trace);
    }

    const budgetValidation = this.#validateBudget(goal.budget, trace);
    if (budgetValidation) {
      return budgetValidation;
    }

    const budget: GoalBudget = goal.budget;
    if (goal.requestedVerbSequence.length > budget.maxSteps) {
      const reason =
        "goal.requestedVerbSequence length " +
        String(goal.requestedVerbSequence.length) +
        " exceeds budget.maxSteps=" +
        String(budget.maxSteps);
      trace.push("budget_exceeded:maxSteps");
      this.#emitObs({
        observationType: "planner:plan_rejected",
        at: this.#isoTimestamp(),
        goalId: goal.goalId,
        reason,
        trace: [...trace],
      });
      return {
        disposition: "budget_exceeded_rejected",
        reason,
        trace: Object.freeze([...trace]),
      };
    }

    const steps: PlanStep[] = [];
    const unionCapSet = new Set<string>();
    let maxSideEncountered: SideEffectClassUpperBound = "none";
    let anyApprovalNeeded = false;

    for (let i = 0; i < goal.requestedVerbSequence.length; i++) {
      const verbId = goal.requestedVerbSequence[i];
      const stepIndex = i;

      if (typeof verbId !== "string" || verbId.length === 0) {
        const reason =
          "step[" + String(stepIndex) + "]: verb id must be a non-empty string";
        trace.push("invalid_verb_id_at_step_" + stepIndex);
        this.#emitObs({
          observationType: "planner:step_rejected",
          at: this.#isoTimestamp(),
          goalId: goal.goalId,
          stepIndex,
          verbId: String(verbId),
          reason,
          trace: [...trace],
        });
        return {
          disposition: "unknown_verb_rejected",
          rejectedStepIndex: stepIndex,
          rejectedVerbId: String(verbId),
          reason,
          trace: Object.freeze([...trace]),
        };
      }

      const lookup = this.#registry.get(verbId);
      if (!lookup.found) {
        const reason = lookup.reason;
        trace.push("unknown_verb:" + verbId);
        this.#emitObs({
          observationType: "planner:step_rejected",
          at: this.#isoTimestamp(),
          goalId: goal.goalId,
          stepIndex,
          verbId,
          reason,
          trace: [...trace],
        });
        return {
          disposition: "unknown_verb_rejected",
          rejectedStepIndex: stepIndex,
          rejectedVerbId: verbId,
          reason,
          trace: Object.freeze([...trace]),
        };
      }

      const verb: VerbContract = lookup.verb;
      if (!isSideEffectClass(verb.sideEffectClass)) {
        const reason =
          "verb '" +
          verbId +
          "' sideEffectClass '" +
          String(verb.sideEffectClass) +
          "' is not a valid SideEffectClass";
        trace.push("invalid_sideEffect_class:" + verbId);
        this.#emitObs({
          observationType: "planner:step_rejected",
          at: this.#isoTimestamp(),
          goalId: goal.goalId,
          stepIndex,
          verbId,
          sideEffectClass: verb.sideEffectClass as SideEffectClass,
          reason,
          trace: [...trace],
        });
        return {
          disposition: "capability_unsupported_rejected",
          rejectedStepIndex: stepIndex,
          rejectedVerbId: verbId,
          reason,
          trace: Object.freeze([...trace]),
        };
      }

      const verbSE: SideEffectClassUpperBound = verb.sideEffectClass;
      if (
        budget.maxSideEffectClass !== undefined &&
        isSideEffectClassUpperBound(budget.maxSideEffectClass)
      ) {
        const verbRank =
          verbSE === "none" ||
          verbSE === "read" ||
          verbSE === "write" ||
          verbSE === "network" ||
          verbSE === "system"
            ? (verbSE as SideEffectClassUpperBound)
            : ("system" as SideEffectClassUpperBound);
        const budgetRank = budget.maxSideEffectClass;
        if (rankOf(verbRank) > rankOf(budgetRank)) {
          const reason =
            "step[" +
            String(stepIndex) +
            "] verb '" +
            verbId +
            "' sideEffectClass '" +
            verbSE +
            "' exceeds budget.maxSideEffectClass '" +
            budgetRank +
            "'";
          trace.push("budget_exceeded:sideEffectClass");
          this.#emitObs({
            observationType: "planner:step_rejected",
            at: this.#isoTimestamp(),
            goalId: goal.goalId,
            stepIndex,
            verbId,
            sideEffectClass: verb.sideEffectClass as SideEffectClass,
            reason,
            trace: [...trace],
          });
          return {
            disposition: "budget_exceeded_rejected",
            rejectedStepIndex: stepIndex,
            rejectedVerbId: verbId,
            reason,
            trace: Object.freeze([...trace]),
          };
        }
      }

      const caps = verb.requiredCapabilities;
      for (const cap of caps) {
        if (typeof cap !== "string" || cap.length === 0) {
          const reason =
            "step[" +
            String(stepIndex) +
            "] verb '" +
            verbId +
            "' declares a non-string capability";
          trace.push("invalid_capability_at_step_" + stepIndex);
          return {
            disposition: "capability_unsupported_rejected",
            rejectedStepIndex: stepIndex,
            rejectedVerbId: verbId,
            reason,
            trace: Object.freeze([...trace]),
          };
        }
        if (
          this.#options.unsupportedCapabilityDeny &&
          !isKnownCapabilityId(cap)
        ) {
          const reason =
            "step[" +
            String(stepIndex) +
            "] verb '" +
            verbId +
            "' requires capability '" +
            cap +
            "' which is not a known CapabilityId";
          trace.push("unknown_capability:" + cap);
          this.#emitObs({
            observationType: "planner:step_rejected",
            at: this.#isoTimestamp(),
            goalId: goal.goalId,
            stepIndex,
            verbId,
            requiredCapabilities: caps,
            reason,
            trace: [...trace],
          });
          return {
            disposition: "capability_unsupported_rejected",
            rejectedStepIndex: stepIndex,
            rejectedVerbId: verbId,
            reason,
            trace: Object.freeze([...trace]),
          };
        }
      }

      const approvalVec: boolean[] = [];
      let stepApproval = false;
      for (const cap of caps) {
        const need = isKnownCapabilityId(cap)
          ? requiresHumanApprovalFor(cap as CapabilityId)
          : true;
        approvalVec.push(need);
        if (need) stepApproval = true;
      }
      if (stepApproval) anyApprovalNeeded = true;

      const frozenCaps: readonly string[] = Object.freeze([...caps]);
      for (const cap of frozenCaps) unionCapSet.add(cap);

      const step: PlanStep = Object.freeze({
        stepIndex,
        verbId,
        requiredCapabilities: frozenCaps,
        sideEffectClass: verbSE,
        description: verb.description,
        replayable: verb.replayable,
        reversible: verb.reversible,
        requiresHumanApproval: Object.freeze([...approvalVec]),
        humanApprovalCount: approvalVec.filter(Boolean).length,
      });

      steps.push(step);

      maxSideEncountered = maxSideEffectClass(maxSideEncountered, verbSE);

      trace.push("step_" + stepIndex + ":" + verbId + ":ok");

      this.#emitObs({
        observationType: "planner:step_validated",
        at: this.#isoTimestamp(),
        goalId: goal.goalId,
        stepIndex,
        verbId,
        requiredCapabilities: frozenCaps,
        sideEffectClass: verb.sideEffectClass as SideEffectClass,
        trace: ["step_approved"],
      });
    }

    const planId = this.#computePlanId(
      goal.goalId,
      startAt,
      steps,
      goal.budget
    );

    const totalCaps: readonly string[] = Object.freeze([...unionCapSet].sort());
    const plan: Plan = Object.freeze({
      planId,
      goalId: goal.goalId,
      steps: Object.freeze([...steps]),
      totalRequiredCapabilities: totalCaps,
      maxSideEffectClassEncountered: maxSideEncountered,
      budget: Object.freeze({ ...goal.budget }),
      humanApprovalRequiredOverall: anyApprovalNeeded,
      createdAt: startAt,
    });

    this.#emitObs({
      observationType: "planner:plan_proposed",
      at: this.#isoTimestamp(),
      goalId: goal.goalId,
      planId,
      trace: [
        "steps:" + String(steps.length),
        "caps:" + String(totalCaps.length),
        "approval:" + String(anyApprovalNeeded),
      ],
    });

    return {
      disposition: "proposed",
      plan,
      reason: "deterministic plan generated from registry state",
      trace: Object.freeze([...trace]),
    };
  }

  buildGraph(plan: Plan, options: BuildPlanGraphOptions = {}): PlanGraph {
    return buildPlanGraph(plan, options);
  }

  #validateBudget(budget: GoalBudget | undefined, trace: string[]): PlannerProposal | null {
    if (!budget || typeof budget !== "object") {
      trace.push("budget_missing_or_invalid");
      return this.#rejectEmpty(
        "budget_exceeded_rejected",
        "goal.budget must be an object with maxSteps",
        trace
      );
    }
    if (
      typeof budget.maxSteps !== "number" ||
      !Number.isFinite(budget.maxSteps) ||
      budget.maxSteps < 0 ||
      Math.floor(budget.maxSteps) !== budget.maxSteps
    ) {
      trace.push("budget_maxSteps_invalid");
      return this.#rejectEmpty(
        "budget_exceeded_rejected",
        "goal.budget.maxSteps must be a non-negative finite integer",
        trace
      );
    }
    if (budget.maxRuntimeMs !== undefined) {
      if (
        typeof budget.maxRuntimeMs !== "number" ||
        !Number.isFinite(budget.maxRuntimeMs) ||
        budget.maxRuntimeMs < 0
      ) {
        trace.push("budget_maxRuntimeMs_invalid");
        return this.#rejectEmpty(
          "budget_exceeded_rejected",
          "goal.budget.maxRuntimeMs must be a non-negative finite number if provided",
          trace
        );
      }
    }
    if (budget.maxSideEffectClass !== undefined) {
      if (!isSideEffectClassUpperBound(budget.maxSideEffectClass)) {
        trace.push("budget_maxSideEffectClass_invalid");
        return this.#rejectEmpty(
          "budget_exceeded_rejected",
          "goal.budget.maxSideEffectClass must be a valid SideEffectClassUpperBound",
          trace
        );
      }
    }
    return null;
  }

  #rejectEmpty(
    disposition: PlannerDisposition,
    reason: string,
    trace: string[]
  ): PlannerProposal {
    return {
      disposition,
      reason,
      trace: Object.freeze([...trace]),
    };
  }

  #computePlanId(
    goalId: string,
    createdAt: string,
    steps: readonly PlanStep[],
    budget: GoalBudget
  ): string {
    const NL = "\n";
    const parts: string[] = [];
    parts.push("goalId:" + goalId);
    parts.push("createdAt:" + createdAt);
    parts.push(
      "budget:" +
        String(budget.maxSteps) +
        "|" +
        (budget.maxRuntimeMs !== undefined ? String(budget.maxRuntimeMs) : "") +
        "|" +
        (budget.maxSideEffectClass !== undefined ? budget.maxSideEffectClass : "")
    );
    for (const s of steps) {
      parts.push(
        String(s.stepIndex) +
          ":" +
          s.verbId +
          ":" +
          s.sideEffectClass +
          ":" +
          s.requiredCapabilities.join(",") +
          ":" +
          String(s.replayable) +
          ":" +
          String(s.reversible)
      );
    }
    const raw = parts.join(NL);
    let h1 = 1779033703;
    let h2 = 3144134277;
    for (let i = 0; i < raw.length; i++) {
      const c = raw.charCodeAt(i);
      h1 = Math.imul(h1 ^ c, 2654435761);
      h1 = (h1 << 13) | (h1 >>> 19);
      h2 = Math.imul(h2 ^ c, 1597334677);
      h2 = (h2 << 11) | (h2 >>> 21);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
    h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
    h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(h1 >>> 0, 0);
    buf.writeUInt32BE(h2 >>> 0, 4);
    const hex = buf.toString("hex");
    return "plan-" + hex;
  }

  #isoTimestamp(): string {
    return new Date().toISOString();
  }

  #emitObs(event: Omit<PlannerObservationEvent, "schemaVersion">): void {
    if (!this.#options.emitObservabilityEvents) return;
    const full: PlannerObservationEvent = Object.freeze({
      schemaVersion: PLANNER_SCHEMA_VERSION,
      ...event,
      trace: Object.isFrozen(event.trace) ? event.trace : Object.freeze([...event.trace]),
    });
    this.#observations.push(full);
  }
}

function rankOf(value: SideEffectClassUpperBound): number {
  switch (value) {
    case "none":
      return 0;
    case "read":
      return 1;
    case "write":
      return 2;
    case "network":
      return 3;
    case "system":
      return 4;
    default:
      return 4;
  }
}

const KNOWN_CAP_ID_STRINGS: ReadonlySet<string> = (function () {
  const set = new Set<string>();
  for (const entry of Object.keys(CAPABILITY_EFFECT_TABLE)) {
    set.add(entry);
  }
  return set;
})();

function isKnownCapabilityId(value: string): boolean {
  return KNOWN_CAP_ID_STRINGS.has(value);
}

export { PLANNER_SCHEMA_VERSION };
