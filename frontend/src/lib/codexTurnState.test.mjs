import assert from "node:assert/strict";
import test from "node:test";
import {
  syncCodexTurnStateDraft,
  editCodexTurnStateDraft,
  formatCodexTurnStateIssued,
} from "./codexTurnState.ts";

const snapshot = (value = "pinned-292", setAt = "2020-01-01T00:00:00Z") => ({
  codex_turn_state: value,
  codex_turn_state_set_at: setAt,
});

test("poll results fill untouched input after refinement stops", () => {
  const initial = syncCodexTurnStateDraft(null, {});
  const latest = { ...snapshot(), codex_turn_state_refining: false };
  const filled = syncCodexTurnStateDraft(initial, latest);
  assert.equal(filled.value, "pinned-292");
  assert.equal(filled.dirty, false);
  const replaced = syncCodexTurnStateDraft(filled, snapshot("next-292", "2026-09-20T10:00:00Z"));
  assert.equal(replaced.value, "next-292");
  assert.equal(replaced.setAt, "2026-09-20T10:00:00Z");
});

test("292 tokens remain pinned regardless of old, missing, invalid or future timestamps", () => {
  for (const setAt of ["2000-01-01T00:00:00Z", "", undefined, "invalid", "2099-01-01T00:00:00Z"]) {
    const server = { codex_turn_state: "pinned-292", codex_turn_state_set_at: setAt };
    const initial = syncCodexTurnStateDraft(null, server);
    assert.equal(initial.value, "pinned-292");
    assert.equal(syncCodexTurnStateDraft(initial, server), initial);
    assert.equal(initial.dirty, false);
  }
});

test("updating only the recorded timestamp retains the same token", () => {
  const initial = syncCodexTurnStateDraft(null, snapshot());
  const updated = syncCodexTurnStateDraft(initial, snapshot("pinned-292", "2026-09-20T10:00:00Z"));
  assert.equal(updated.value, "pinned-292");
  assert.equal(updated.setAt, "2026-09-20T10:00:00Z");
  assert.equal(updated.dirty, false);
});

test("manual new token and explicit clear survive repeated background pin and clear", () => {
  for (const value of ["unsaved-token", ""]) {
    let draft = syncCodexTurnStateDraft(null, snapshot());
    draft = editCodexTurnStateDraft(draft, value);
    assert.equal(draft.dirty, true);
    for (const server of [snapshot("background-292"), {}, snapshot()]) {
      draft = syncCodexTurnStateDraft(draft, server);
      assert.equal(draft.value, value);
      assert.equal(draft.dirty, true);
    }
  }
});

test("backend clear still clears an untouched field", () => {
  const initial = syncCodexTurnStateDraft(null, snapshot());
  const cleared = syncCodexTurnStateDraft(initial, {});
  assert.deepEqual(cleared, { value: "", savedValue: "", setAt: "", dirty: false });
});

test("reverting a manual edit to the latest server value resumes synchronization", () => {
  let draft = syncCodexTurnStateDraft(null, snapshot());
  draft = editCodexTurnStateDraft(draft, "unsaved-token");
  draft = syncCodexTurnStateDraft(draft, snapshot("next-292"));
  draft = editCodexTurnStateDraft(draft, "next-292");
  assert.equal(draft.dirty, false);
  assert.equal(syncCodexTurnStateDraft(draft, {}).value, "");
});

test("issued time formats a valid embedded timestamp without refresh warning", () => {
  const issued = formatCodexTurnStateIssued(
    "2026-09-20T14:28:05Z",
    Date.parse("2026-09-20T14:30:00Z"),
  );
  assert.deepEqual(issued, { text: "2026-09-20 14:28 UTC", nearRefresh: false });
});

test("issued time is hidden for empty, missing or invalid values", () => {
  for (const value of ["", "   ", undefined, "not-a-date", "2026-13-99"]) {
    assert.equal(formatCodexTurnStateIssued(value), null);
  }
});

test("issued time flags the last 20 minutes and expired tokens as near refresh", () => {
  const issuedAt = "2026-09-20T14:28:00Z";
  const insideWindow = formatCodexTurnStateIssued(issuedAt, Date.parse("2026-09-20T15:09:00Z"));
  assert.equal(insideWindow.nearRefresh, true);
  const expired = formatCodexTurnStateIssued(issuedAt, Date.parse("2026-09-20T15:30:00Z"));
  assert.equal(expired.nearRefresh, true);
  const outsideWindow = formatCodexTurnStateIssued(issuedAt, Date.parse("2026-09-20T15:08:00Z"));
  assert.equal(outsideWindow.nearRefresh, false);
});
