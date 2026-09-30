import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../api/client.js";

const ACTIVE_STATUSES = new Set([
  "queued",
  "running",
  "cancelling",
  "recovering",
]);

export function useOperationDetail() {
  const [selected, setSelected] = useState(null);
  const [detailError, setDetailError] = useState(null);
  const [detailBusy, setDetailBusy] = useState(false);
  const current = useRef(null);
  const session = useRef(0);
  const request = useRef(0);
  const pending = useRef(false);

  const closeDetail = useCallback(() => {
    session.current += 1;
    request.current += 1;
    pending.current = false;
    current.current = null;
    setSelected(null);
    setDetailError(null);
    setDetailBusy(false);
  }, []);

  useEffect(
    () => () => {
      session.current += 1;
      request.current += 1;
      current.current = null;
    },
    [],
  );

  const refreshDetail = useCallback(async () => {
    const operation = current.current;
    if (!operation || pending.current) return;
    const activeSession = session.current;
    const ticket = ++request.current;
    pending.current = true;
    setDetailBusy(true);
    try {
      const detail = await api(
        "/api/operations/" + encodeURIComponent(operation.operation_id),
      );
      if (session.current !== activeSession || request.current !== ticket)
        return;
      current.current = detail;
      setSelected(detail);
      setDetailError(null);
    } catch (error) {
      if (session.current === activeSession && request.current === ticket)
        setDetailError(error);
    } finally {
      if (session.current === activeSession && request.current === ticket) {
        pending.current = false;
        setDetailBusy(false);
      }
    }
  }, []);

  const openDetail = useCallback(
    async (operation) => {
      session.current += 1;
      request.current += 1;
      pending.current = false;
      current.current = operation;
      setSelected(operation);
      setDetailError(null);
      await refreshDetail();
    },
    [refreshDetail],
  );

  const updateDetail = useCallback(async (operation, action) => {
    const activeSession = session.current;
    const visible = current.current?.operation_id === operation.operation_id;
    const ticket = visible ? ++request.current : null;
    if (visible) {
      pending.current = true;
      setDetailBusy(true);
    }
    try {
      const detail = await action();
      if (
        visible &&
        session.current === activeSession &&
        request.current === ticket
      ) {
        current.current = detail;
        setSelected(detail);
        setDetailError(null);
      }
      return detail;
    } finally {
      if (
        visible &&
        session.current === activeSession &&
        request.current === ticket
      ) {
        pending.current = false;
        setDetailBusy(false);
      }
    }
  }, []);

  const operationId = selected?.operation_id;
  const status = selected?.status;
  useEffect(() => {
    if (!operationId || !ACTIVE_STATUSES.has(status)) return;
    const timer = window.setInterval(refreshDetail, 2000);
    return () => window.clearInterval(timer);
  }, [operationId, status, refreshDetail]);

  return {
    selected,
    openDetail,
    closeDetail,
    refreshDetail,
    updateDetail,
    detailError,
    detailBusy,
  };
}
