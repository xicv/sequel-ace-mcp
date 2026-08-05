import type { ConfirmOutcome, GrantChoice } from '../elicit/confirm.js';
import type { GrantStore } from './grants.js';
import {
  PolicyConfirmationDeclinedError,
  PolicyConfirmationUnavailableError,
  PolicyDeniedError,
  type Policy,
  type PolicyAction,
  type SqlCategory,
} from '../types.js';

export interface ElicitConfirmFn {
  (params: {
    category: SqlCategory;
    statement: string;
    connectionName: string;
    database?: string | null;
  }): Promise<ConfirmOutcome>;
}

export interface PolicyDecision {
  category: SqlCategory;
  action: PolicyAction;
  confirmed: boolean;
  grantUsed?: 'once' | 'session' | null;
  choiceApplied?: GrantChoice | null;
}

function actionForCategory(policy: Policy, category: SqlCategory): PolicyAction {
  switch (category) {
    case 'read':
      return policy.read;
    case 'write':
      return policy.write;
    case 'ddl':
      return policy.ddl;
    case 'admin':
      return policy.admin;
    case 'txCtrl':
      return policy.txCtrl;
  }
}

export async function evaluatePolicy(args: {
  policy: Policy;
  category: SqlCategory;
  statement: string;
  connectionName: string;
  elicitConfirm: ElicitConfirmFn;
  grants?: GrantStore;
  grantDatabase?: string | null;
}): Promise<PolicyDecision> {
  const action = actionForCategory(args.policy, args.category);
  if (action === 'deny') {
    throw new PolicyDeniedError(args.category, args.statement.slice(0, 200));
  }
  if (action === 'allow') {
    return { category: args.category, action, confirmed: false };
  }

  const grantKey = {
    connection: args.connectionName,
    database: args.grantDatabase ?? null,
    category: args.category,
  };

  if (args.grants?.consume(grantKey)) {
    return {
      category: args.category,
      action,
      confirmed: true,
      grantUsed: 'session',
      choiceApplied: null,
    };
  }

  const outcome = await args.elicitConfirm({
    category: args.category,
    statement: args.statement,
    connectionName: args.connectionName,
    database: args.grantDatabase ?? null,
  });

  // Never shown a prompt at all - do not pass this off as a refusal.
  if (outcome.choice === 'unavailable') {
    throw new PolicyConfirmationUnavailableError(args.category, outcome.reason);
  }

  const choice: GrantChoice = outcome.choice;

  if (choice === 'decline') {
    throw new PolicyConfirmationDeclinedError(args.category);
  }
  if (choice === 'session') {
    args.grants?.grantSession(grantKey);
  }
  return {
    category: args.category,
    action,
    confirmed: true,
    grantUsed: null,
    choiceApplied: choice,
  };
}
