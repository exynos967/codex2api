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

const CODEX_TURN_STATE_LIFETIME_MS = 60 * 60 * 1000
const CODEX_TURN_STATE_REFRESH_WINDOW_MS = 20 * 60 * 1000

const pad2 = (n: number) => String(n).padStart(2, '0')

/**
 * 格式化 token 内嵌签发时间供界面展示。
 * text 是 UTC 时刻(YYYY-MM-DD HH:mm UTC);remainingMs < 20min(含已过期)时
 * nearRefresh 为 true,提示进入提前刷新窗口。空/非法输入返回 null。
 */
export function formatCodexTurnStateIssued(
  issuedAt?: string,
  now: number = Date.now(),
): { text: string; nearRefresh: boolean } | null {
  if (typeof issuedAt !== 'string') return null
  const ms = Date.parse(issuedAt.trim())
  if (!Number.isFinite(ms)) return null
  const d = new Date(ms)
  const text =
    `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())} ` +
    `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())} UTC`
  const remainingMs = ms + CODEX_TURN_STATE_LIFETIME_MS - now
  return { text, nearRefresh: remainingMs < CODEX_TURN_STATE_REFRESH_WINDOW_MS }
}
