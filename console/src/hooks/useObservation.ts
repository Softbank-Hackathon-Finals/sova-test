import { useCallback, useEffect, useRef, useState } from "react";
import {
  ApiError,
  dependencyState,
  mergeSecurityEvents,
  request,
  securityState,
} from "../api";
import type {
  Connection,
  DependencyState,
  Mode,
  SecurityState,
} from "../types";

export function useObservation(mode: Mode, suspended: boolean) {
  const [dependency, setDependency] = useState<DependencyState | null>(null);
  const [security, setSecurity] = useState<SecurityState | null>(null);
  const [connection, setConnection] = useState<Connection>("loading");
  const [error, setError] = useState("");
  const [receivedAt, setReceivedAt] = useState(0);
  const generation = useRef(0);
  const busy = useRef(false);
  const abort = useRef<AbortController | null>(null);
  const latest = useRef({
    dependency: null as DependencyState | null,
    security: null as SecurityState | null,
  });
  const securityCursor = useRef(0);
  const refresh = useCallback(async () => {
    if (busy.current) return;
    busy.current = true;
    const version = generation.current;
    const controller = new AbortController();
    abort.current = controller;
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const data = await request<unknown>(
        mode === "dependency"
          ? "/api/dependency/state"
          : securityCursor.current
            ? `/api/state?after=${securityCursor.current}`
            : "/api/state?recent=1",
        undefined,
        controller.signal,
      );
      if (version !== generation.current) return;
      if (mode === "dependency") {
        const next = dependencyState(data),
          prior = latest.current.dependency;
        if (
          prior &&
          (next.revision < prior.revision ||
            (next.revision === prior.revision && next.now < prior.now))
        )
          return;
        latest.current.dependency = next;
        setDependency(next);
      } else {
        const next = securityState(data),
          prior = latest.current.security;
        if (
          prior &&
          (next.route.revision < prior.route.revision ||
            Date.parse(next.at) < Date.parse(prior.at))
        )
          return;
        next.events = mergeSecurityEvents(prior?.events || [], next.events);
        securityCursor.current = Math.max(
          securityCursor.current,
          ...next.events.map((e) => e.sequence),
        );
        latest.current.security = next;
        setSecurity(next);
      }
      setConnection("connected");
      setError("");
      setReceivedAt(Date.now());
    } catch (cause) {
      if (version !== generation.current) return;
      setConnection(
        cause instanceof ApiError && [401, 403, 404].includes(cause.status)
          ? "expired"
          : "unverified",
      );
      setError(
        cause instanceof Error ? cause.message : "관측을 확인할 수 없습니다.",
      );
    } finally {
      clearTimeout(timer);
      if (version === generation.current) busy.current = false;
    }
  }, [mode]);
  useEffect(() => {
    generation.current++;
    busy.current = false;
    abort.current?.abort();
    setConnection("loading");
    setError("");
    if (!suspended) void refresh();
    const interval = setInterval(() => {
      if (!suspended) void refresh();
    }, 2000);
    return () => {
      generation.current++;
      abort.current?.abort();
      clearInterval(interval);
    };
  }, [mode, refresh, suspended]);
  useEffect(() => {
    const timer = setInterval(() => {
      if (receivedAt && Date.now() - receivedAt > 12000)
        setConnection((c) => (c === "connected" ? "unverified" : c));
    }, 1000);
    return () => clearInterval(timer);
  }, [receivedAt]);
  return { dependency, security, connection, error, receivedAt, refresh };
}
