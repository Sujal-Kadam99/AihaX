/**
 * Scope normalizers to defensively parse and format scope rules and decisions.
 * Handles strings, arrays, raw JSON strings, and structured object assets.
 */

export function normalizeScopeRules(scope) {
  if (!scope) return [];
  let raw = scope.in_scope_assets;
  if (!raw) return [];
  if (typeof raw === 'string') {
    try {
      raw = JSON.parse(raw);
    } catch {
      raw = [raw];
    }
  }
  if (!Array.isArray(raw)) return [];
  return raw
    .map((item) => {
      if (typeof item === 'string') return item.trim();
      if (item && typeof item === 'object') {
        return (
          item.url ||
          item.target ||
          item.raw_scope_definition ||
          item.normalized_scope_definition ||
          item.asset_name ||
          item.asset ||
          JSON.stringify(item)
        );
      }
      return String(item || '').trim();
    })
    .filter(Boolean);
}

export function normalizeMatchedRule(matchedRule) {
  if (!matchedRule) return null;
  if (typeof matchedRule === 'string') return matchedRule;
  if (typeof matchedRule === 'object') {
    return (
      matchedRule.pattern ||
      matchedRule.rule ||
      matchedRule.target ||
      matchedRule.url ||
      matchedRule.raw_scope_definition ||
      JSON.stringify(matchedRule)
    );
  }
  return String(matchedRule);
}

export function normalizeReason(reason) {
  if (!reason) return 'Target validated against authorized scope.';
  if (typeof reason === 'string') return reason;
  if (typeof reason === 'object') {
    return reason.message || reason.detail || reason.reason || JSON.stringify(reason);
  }
  return String(reason);
}
