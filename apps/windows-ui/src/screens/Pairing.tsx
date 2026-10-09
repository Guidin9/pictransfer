import { useCallback, useEffect, useRef, useState } from "react";
import { errorCode, onAgentEvent, rpc } from "../agent";
import { Card, Icon, QrCode } from "../components/ui";
import { platformName, t, type Key } from "../i18n";

export type PairState =
  | { phase: "idle" }
  | { phase: "starting" }
  | { phase: "showing"; qr: string; expiresAt: number }
  | { phase: "expired" }
  | { phase: "sas"; sas: string; peerName: string; peerPlatform: string; busy: boolean }
  | { phase: "waiting" }
  | { phase: "done" }
  | { phase: "failed"; code: string };

export interface Pairing {
  state: PairState;
  start: () => Promise<void>;
  confirm: (accept: boolean) => Promise<void>;
  cancel: () => Promise<void>;
}

/** Pairing state lives at app level so a `pair.sas` event is never missed. */
export function usePairing(onSas: () => void): Pairing {
  const [state, setState] = useState<PairState>({ phase: "idle" });
  const onSasRef = useRef(onSas);
  onSasRef.current = onSas;

  useEffect(
    () =>
      onAgentEvent((e) => {
        if (e.event === "pair.sas") {
          setState({ phase: "sas", sas: e.data.sas, peerName: e.data.peer_name, peerPlatform: e.data.peer_platform, busy: false });
          onSasRef.current();
        } else if (e.event === "pair.done") setState({ phase: "done" });
        else if (e.event === "pair.failed") setState({ phase: "failed", code: e.data.code });
      }),
    [],
  );

  const start = useCallback(async () => {
    setState({ phase: "starting" });
    try {
      const r = await rpc("pair.start");
      setState({ phase: "showing", qr: r.qr_text, expiresAt: r.expires_at });
    } catch (e) {
      setState({ phase: "failed", code: errorCode(e) });
    }
  }, []);

  const confirm = useCallback(async (accept: boolean) => {
    setState((s) => (s.phase === "sas" ? { ...s, busy: true } : s));
    try {
      await rpc("pair.confirm", { accept });
      setState(accept ? { phase: "waiting" } : { phase: "failed", code: "rejected" });
    } catch (e) {
      setState({ phase: "failed", code: errorCode(e) });
    }
  }, []);

  const cancel = useCallback(async () => {
    setState({ phase: "idle" });
    try {
      await rpc("pair.cancel");
    } catch {
      /* the window closes on the agent side anyway */
    }
  }, []);

  return { state, start, confirm, cancel };
}

function useCountdown(until: number | null): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (until === null) return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [until]);
  return until === null ? 0 : Math.min(120, Math.max(0, Math.ceil((until - now) / 1000)));
}

const FAILED_KEYS: Record<string, Key> = {
  expired: "pair.failed.expired",
  proof: "pair.failed.proof",
  rejected: "pair.failed.rejected",
  "other-group": "pair.failed.other-group",
  network: "pair.failed.network",
};

export function PairingPage({ pairing }: { pairing: Pairing }) {
  const { state, start, confirm, cancel } = pairing;
  const left = useCountdown(state.phase === "showing" ? state.expiresAt : null);
  const stateRef = useRef(state);
  stateRef.current = state;

  // Leaving the page while the code is shown closes the pairing window.
  useEffect(
    () => () => {
      if (stateRef.current.phase === "showing") void cancel();
    },
    [cancel],
  );

  const expired = state.phase === "expired" || (state.phase === "showing" && left === 0);

  return (
    <div className="page">
      <h1>{t("pair.title")}</h1>
      <Card className="pair-card">
        {(state.phase === "idle" || state.phase === "starting") && (
          <div className="pair-intro">
            <div className="hero-icon">
              <Icon name="phone" />
            </div>
            <p>{t("pair.intro")}</p>
            <button type="button" className="btn accent" disabled={state.phase === "starting"} onClick={() => void start()}>
              {t("pair.start")}
            </button>
          </div>
        )}

        {state.phase === "showing" && !expired && (
          <div className="pair-qr">
            <QrCode text={state.qr} label={t("pair.qr.alt")} />
            <div className="pair-side">
              <p>{t("pair.intro")}</p>
              <div className="countdown">
                <div className="bar">
                  <div className="fill" style={{ width: `${(left / 120) * 100}%` }} />
                </div>
                <span>{t("pair.expiresIn", { s: left })}</span>
              </div>
              <button type="button" className="btn" onClick={() => void cancel()}>
                {t("common.cancel")}
              </button>
            </div>
          </div>
        )}

        {expired && (
          <div className="pair-intro">
            <p>{t("pair.expired")}</p>
            <button type="button" className="btn accent" onClick={() => void start()}>
              {t("pair.again")}
            </button>
          </div>
        )}

        {state.phase === "sas" && (
          <div className="pair-sas">
            <h2>{t("pair.sas.title")}</h2>
            <div className="sas" aria-live="polite">
              {state.sas}
            </div>
            <p>{t("pair.sas.body", { name: state.peerName, platform: platformName(state.peerPlatform) })}</p>
            <div className="actions">
              <button type="button" className="btn accent" disabled={state.busy} onClick={() => void confirm(true)}>
                <Icon name="check" />
                {t("pair.confirm")}
              </button>
              <button type="button" className="btn" disabled={state.busy} onClick={() => void confirm(false)}>
                <Icon name="close" />
                {t("pair.reject")}
              </button>
            </div>
          </div>
        )}

        {state.phase === "waiting" && (
          <div className="pair-intro">
            <div className="spinner" />
            <p>{t("pair.waiting")}</p>
          </div>
        )}

        {state.phase === "done" && (
          <div className="pair-intro">
            <div className="hero-icon ok">
              <Icon name="check" />
            </div>
            <p>{t("pair.done")}</p>
            <button type="button" className="btn" onClick={() => void start()}>
              {t("pair.again")}
            </button>
          </div>
        )}

        {state.phase === "failed" && (
          <div className="pair-intro">
            <div className="hero-icon bad">
              <Icon name="close" />
            </div>
            <p>{FAILED_KEYS[state.code] ? t(FAILED_KEYS[state.code] as Key) : t("common.error", { code: state.code })}</p>
            <button type="button" className="btn accent" onClick={() => void start()}>
              {t("pair.again")}
            </button>
          </div>
        )}
      </Card>
    </div>
  );
}
