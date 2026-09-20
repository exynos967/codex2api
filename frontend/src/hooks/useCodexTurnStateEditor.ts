import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { AccountRow } from "../types";
import {
  editCodexTurnStateDraft,
  syncCodexTurnStateDraft,
} from "../lib/codexTurnState";

/** 弹窗独立读取单账号详情,不依赖列表分页或死磕进行中状态。 */
export function useCodexTurnStateEditor(account: AccountRow | null, enabled: boolean) {
  const [liveAccount, setLiveAccount] = useState(account);
  const [draft, setDraft] = useState(() => syncCodexTurnStateDraft(null, account ?? {}));
  const refreshRef = useRef<(id: number) => void>(() => {});

  useEffect(() => {
    setLiveAccount(account);
    setDraft(syncCodexTurnStateDraft(null, account ?? {}));
    if (!account || !enabled) return;

    const controller = new AbortController();
    let timer: number | undefined;
    let running = false;
    let queued = false;
    const poll = async () => {
      if (controller.signal.aborted) return;
      if (running) {
        queued = true;
        return;
      }
      running = true;
      try {
        const latest = await api.getAccount(account.id, controller.signal);
        if (controller.signal.aborted) return;
        setLiveAccount(latest);
        setDraft((current) => syncCodexTurnStateDraft(current, latest));
      } catch {
        // 暂时断网保留草稿,下轮继续同步。
      } finally {
        running = false;
        if (!controller.signal.aborted) {
          timer = window.setTimeout(() => void poll(), queued ? 0 : 5000);
          queued = false;
        }
      }
    };
    refreshRef.current = (id) => {
      if (id !== account.id) return;
      window.clearTimeout(timer);
      void poll();
    };
    void poll();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
      refreshRef.current = () => {};
    };
  }, [account, enabled]);

  const setValue = useCallback((value: string) => {
    setDraft((current) => editCodexTurnStateDraft(current, value));
  }, []);
  const refresh = useCallback((id: number) => refreshRef.current(id), []);

  return { liveAccount, draft, setValue, refresh };
}
