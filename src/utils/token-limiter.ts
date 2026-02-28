// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors
import { encoding_for_model, TiktokenModel } from 'tiktoken';

export interface TokenCheckResult {
  allowed: boolean;
  tokens: number;
  error?: string;
}

/**
 * Calculate the number of tokens in a text using tiktoken (GPT-4 tokenizer).
 * Falls back to a rough estimate (text.length / 4) if tiktoken fails.
 */
export function calculateTokens(text: string, model: TiktokenModel = 'gpt-4'): number {
  try {
    const encoding = encoding_for_model(model);
    const tokens = encoding.encode(text);
    const count = tokens.length;
    encoding.free();
    return count;
  } catch {
    return Math.ceil(text.length / 4);
  }
}

/**
 * Check if the tool result exceeds the token limit.
 * @param result     The tool result object to check (will be JSON.stringified for token count)
 * @param maxTokens  Maximum allowed tokens
 * @param breakRule  If true, bypass the limit and always allow (emergency override)
 */
export function checkTokenLimit(
  result: unknown,
  maxTokens: number,
  breakRule = false
): TokenCheckResult {
  if (breakRule) {
    return { allowed: true, tokens: 0 };
  }

  const resultText = JSON.stringify(result);
  const tokens = calculateTokens(resultText);

  if (tokens > maxTokens) {
    return {
      allowed: false,
      tokens,
      error:
        `Token limit exceeded: result contains ${tokens} tokens (limit: ${maxTokens}).\n\n` +
        'Suggestions:\n' +
        '1. Reduce the "limit" parameter to fetch fewer items (e.g., limit: 50)\n' +
        '2. Use "skip" + "limit" for pagination instead of fetching all at once\n' +
        '3. Add "count: true" to get just the total count first\n' +
        '4. Use more specific search filters to narrow results\n' +
        '5. If absolutely necessary, retry with break_token_rule: true\n\n' +
        'Note: Frequent use of break_token_rule may cause context overflow and degraded AI performance.',
    };
  }

  return { allowed: true, tokens };
}
