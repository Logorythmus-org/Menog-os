import type {
  Actor,
  MenogEventInput,
} from "@menog/core";
import type { PlannerObservationEvent } from "./deterministicPlanner.js";

const PLANNER_EVENT_SCHEMA = "menog-planner-ledger-bridge/v0";

function observationToEventType(obsType: PlannerObservationEvent["observationType"]): string {
  switch (obsType) {
    case "planner:goal_received":
      return "planner_goal_received";
    case "planner:step_validated":
      return "planner_step_validated";
    case "planner:step_rejected":
      return "planner_step_rejected";
    case "planner:plan_proposed":
      return "planner_plan_proposed";
    case "planner:plan_rejected":
      return "planner_plan_rejected";
    default:
      return "planner_observation_unknown";
  }
}

function policyDecisionFromObservation(
  obsType: PlannerObservationEvent["observationType"]
): "allow" | "deny" | "not_applicable" {
  switch (obsType) {
    case "planner:step_rejected":
    case "planner:plan_rejected":
      return "deny";
    case "planner:step_validated":
    case "planner:plan_proposed":
      return "allow";
    case "planner:goal_received":
    default:
      return "not_applicable";
  }
}

export function plannerObservationToMenogEventInputs(
  observations: readonly PlannerObservationEvent[],
  actor: Actor,
  options: {
    readonly workspaceId?: string;
    readonly taskId?: string;
    readonly eventIdPrefix?: string;
  } = {}
): readonly MenogEventInput[] {
  const prefix =
    typeof options.eventIdPrefix === "string" && options.eventIdPrefix.length > 0
      ? options.eventIdPrefix
      : "plr";
  const out: MenogEventInput[] = [];
  const nowIsoBase = new Date().toISOString();

  for (let i = 0; i < observations.length; i++) {
    const obs = observations[i]!;
    const seq = String(i).padStart(4, "0");
    const ts =
      typeof obs.at === "string" && obs.at.length > 0 ? obs.at : nowIsoBase;
    const capsJoined =
      Array.isArray(obs.requiredCapabilities) && obs.requiredCapabilities.length > 0
        ? obs.requiredCapabilities.slice().sort().join("+")
        : "none";
    const decision = policyDecisionFromObservation(obs.observationType);
    const eventType = observationToEventType(obs.observationType);
    const eventId = prefix + "-" + obs.goalId.slice(0, 12) + "-" + seq;

    const evt: MenogEventInput = {
      eventId,
      timestamp: ts,
      eventType,
      actor: { type: actor.type, id: actor.id },
      workspaceId: options.workspaceId,
      taskId: options.taskId,
      verb: typeof obs.verbId === "string" ? obs.verbId : undefined,
      capability: capsJoined === "none" ? undefined : capsJoined,
      policyDecision: decision,
      inputSummary: Object.freeze({
        schema: PLANNER_EVENT_SCHEMA,
        observationType: obs.observationType,
        plannerSchemaVersion: obs.schemaVersion,
        goalId: obs.goalId,
        planId: typeof obs.planId === "string" ? obs.planId : null,
        stepIndex: typeof obs.stepIndex === "number" ? obs.stepIndex : null,
        verbId: typeof obs.verbId === "string" ? obs.verbId : null,
        trace: obs.trace.slice(),
      }),
      resultSummary: Object.freeze({
        disposition: decision,
        reason: typeof obs.reason === "string" ? obs.reason : null,
        sideEffectClass:
          typeof obs.sideEffectClass === "string" ? obs.sideEffectClass : null,
        requiredCapabilities: obs.requiredCapabilities?.slice() ?? [],
      }),
    };
    out.push(evt);
  }

  return Object.freeze(out);
}
