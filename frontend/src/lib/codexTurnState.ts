// Turn-State 草稿同步:后台固定值持续保留,不按设置时间过期。

export interface CodexTurnStateSnapshot {
  codex_turn_state?: string
  codex_turn_state_set_at?: string
}

export interface CodexTurnStateDraft {
  value: string
  savedValue: string
  setAt: string
  dirty: boolean
}

/** 只同步注入值与时间;手动输入(包括清空)不被后台更新覆盖。 */
export function syncCodexTurnStateDraft(
  draft: CodexTurnStateDraft | null,
  snapshot: CodexTurnStateSnapshot,
): CodexTurnStateDraft {
  const savedValue = snapshot.codex_turn_state ?? ''
  const setAt = snapshot.codex_turn_state_set_at ?? ''
  const next = {
    value: draft?.dirty ? draft.value : savedValue,
    savedValue,
    setAt,
    dirty: draft?.dirty ?? false,
  }
  if (draft && draft.value === next.value && draft.savedValue === savedValue &&
      draft.setAt === setAt && draft.dirty === next.dirty) return draft
  return next
}

export function editCodexTurnStateDraft(
  draft: CodexTurnStateDraft,
  value: string,
): CodexTurnStateDraft {
  return { ...draft, value, dirty: value !== draft.savedValue }
}
