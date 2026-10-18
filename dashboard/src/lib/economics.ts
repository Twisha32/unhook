import type { CostAssumptions } from "./types";

// A client-side copy of backend/unhook/eval/metrics.py, so the Evaluation page can
// recompute everything from the stored test scores as the sliders move.

export interface Split { mal: number; sus: number; low: number }

export function split(scores: number[], suspicious: number, malicious: number): Split {
  const n = Math.max(scores.length, 1);
  let mal = 0, sus = 0;
  for (const s of scores) {
    if (s >= malicious) mal++;
    else if (s >= suspicious) sus++;
  }
  return { mal: mal / n, sus: sus / n, low: 1 - (mal + sus) / n };
}

export function economics(phish: Split, ham: Split, a: CostAssumptions) {
  const pi = a.prevalence;
  const review = 1000 * (pi * (phish.mal * a.malicious_review_minutes + phish.sus * a.triaged_review_minutes)
    + (1 - pi) * (ham.mal * a.malicious_review_minutes + ham.sus * a.triaged_review_minutes));
  const missed = 1000 * pi * phish.low;
  const falseBlocks = 1000 * (1 - pi) * ham.mal;
  const baseline = 1000 * a.manual_minutes;
  const total = review + missed * a.miss_minutes + falseBlocks * a.block_error_minutes;
  // "saved" is review time only. "net" is what's left after paying for the mistakes.
  return { baseline, review, saved: baseline - review, net: baseline - total, missed, falseBlocks, total };
}

export function flagMetrics(phish: Split, ham: Split, prevalence: number) {
  const recall = 1 - phish.low;
  const fpr = 1 - ham.low;
  const tp = recall * prevalence;
  const fp = fpr * (1 - prevalence);
  return { recall, fpr, precision: tp + fp === 0 ? 1 : tp / (tp + fp) };
}
