import type { GrantChoice } from '../elicit/confirm.js';
import type { GrantStore } from './grants.js';
import {
  PolicyConfirmationDeclinedError,
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
  }): Promise<GrantChoice>;
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
  onAlwaysGrant?: (category: SqlCategory) => Promise<void> | void;
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

  const choice = await args.elicitConfirm({
    category: args.category,
    statement: args.statement,
    connectionName: args.connectionName,
  });

  if (choice === 'decline') {
    throw new PolicyConfirmationDeclinedError(args.category);
  }
  if (choice === 'session') {
    args.grants?.grantSession(grantKey);
  } else if (choice === 'always') {
    if (args.onAlwaysGrant) {
      await args.onAlwaysGrant(args.category);
    }
  }
  return {
    category: args.category,
    action,
    confirmed: true,
    grantUsed: null,
    choiceApplied: choice,
  };
}
