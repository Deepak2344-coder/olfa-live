// Mock analyze logic. Pure functions only (no chrome.*), so node can test it.
// The fixture data lives in mock/contracts.js, generated from /shared/contracts
// by `npm run sync-mock`.
import { sleep } from "./logic.js";

const MOCK_DELAY_MS = 1000;

/**
 * Pick the /shared/contracts example to fake for `url`, by keyword.
 * Unmatched URLs fall back to the first fixture (dangerous, the richest one).
 * @param {string} url
 * @param {Array<{keywords: string[], data: object}>} contracts
 * @returns {object}
 */
export function pickContract(url, contracts) {
  const text = String(url).toLowerCase();
  for (const entry of contracts) {
    if (entry.keywords.some((k) => text.includes(k))) return entry.data;
  }
  return contracts[0].data;
}

/**
 * Fake analyze: returns the picked contract after a short delay. The URL we
 * were given replaces the fixture's example URL.
 * @param {string} url
 * @param {Array<{keywords: string[], data: object}>} contracts
 * @returns {Promise<object>}
 */
export async function mockAnalyze(url, contracts) {
  await sleep(MOCK_DELAY_MS);
  return { ...pickContract(url, contracts), url };
}

/**
 * Fake report submission.
 * @param {object} payload
 * @returns {Promise<object>}
 */
export async function mockReport(payload) {
  await sleep(300);
  return {
    id: `rep_mock_${Math.random().toString(16).slice(2, 10)}`,
    ...payload,
    status: "pending",
    created_at: new Date().toISOString(),
  };
}
