import { useCallback, useEffect, useRef, useState } from "react";
import { errorCode, onAgentEvent, onConnection, ready, rpc, type AgentEvent, type Status } from "./agent";
import { Icon } from "./components/ui";
import { platformName, t, type Key } from "./i18n";
import { DevicesPage } from "./screens/Devices";
import { HistoryPage } from "./screens/History";
import { ActiveTransfers } from "./components/ActiveTransfers";
import { PairingPage, usePairing } from "./screens/Pairing";
import { SettingsPage } from "./screens/Settings";

type Page = "pairing" | "devices" | "settings" | "history";
type Conn = "connecting" | "up" | "down" | "untrusted";
type GroupAlert = Extract<AgentEvent, { event: "group.alert" }>["data"];

const NAV: { id: Page; label: Key; icon: "pair" | "devices" | "settings" | "history" }[] = [
  { id: "devices", label: "nav.devices", icon: "devices" },
  { id: "pairing", label: "nav.pairing", icon: "pair" },
  { id: "settings", label: "nav.settings", icon: "settings" },
  { id: "history", label: "nav.history", icon: "history" },
];

const RETRY_MS = 3000;

export function App() {
  const [conn, setConn] = useState<Conn>("connecting");
  const [lost, setLost] = useState(false);
  const [status, setStatus] = useState<Status | null>(null);
  const [page, setPage] = useState<Page>("devices");
  const [alerts, setAlerts] = useState<GroupAlert[]>([]);
  const [fork, setFork] = useState(false);
  const [alertBusy, setAlertBusy] = useState(false);
  const retry = useRef<number | undefined>(undefined);
  const pairing = usePairing(() => setPage("pairing"));

  const connect = useCallback(async () => {
    window.clearTimeout(retry.current);
    try {
      await ready();
      const s = await rpc("status");
      setStatus(s);
      setConn("up");
      setLost(false);
      setPage((p) => (p === "devices" && !s.paired ? "pairing" : p));
    } catch (e) {
      const code = errorCode(e);
      setConn(code === "agent-untrusted" ? "untrusted" : "down");
      retry.current = window.setTimeout(() => void connect(), RETRY_MS);
    }
  }, []);

  useEffect(() => {
    void connect();
    const offConn = onConnection((up) => {
      if (!up) {
        setLost(true);
        retry.current = window.setTimeout(() => void connect(), 500);
      }
    });
    const offEv = onAgentEvent((e) => {
      if (e.event === "status") setStatus(e.data);
      else if (e.event === "group.alert") setAlerts((a) => [...a.filter((x) => x.id !== e.data.id), e.data]);
      else if (e.event === "group.fork") setFork(true);
    });
    return () => {
      offConn();
      offEv();
      window.clearTimeout(retry.current);
    };
  }, [connect]);

  const notMe = async (a: GroupAlert) => {
    setAlertBusy(true);
    try {
      await rpc("group.not_me", { id: a.id });
      setAlerts((xs) => xs.filter((x) => x.id !== a.id));
    } catch {
      /* keep the banner; the user can retry */
    } finally {
      setAlertBusy(false);
    }
  };

  if (conn === "connecting") {
    return (
      <div className="center-state">
        <div className="spinner" />
        <p>{t("agent.connecting")}</p>
      </div>
    );
  }
  if (conn === "down" || conn === "untrusted") {
    const untrusted = conn === "untrusted";
    return (
      <div className="center-state">
        <div className="state-icon">
          <Icon name={untrusted ? "shield" : "plug"} />
        </div>
        <h1>{t(untrusted ? "agent.untrusted.title" : "agent.notRunning.title")}</h1>
        <p>{t(untrusted ? "agent.untrusted.body" : "agent.notRunning.body")}</p>
        <button type="button" className="btn accent" onClick={() => void connect()}>
          {t("agent.retry")}
        </button>
      </div>
    );
  }

  return (
    <div className="shell">
      <nav className="nav">
        <div className="me">
          <div className="me-icon">
            <Icon name="pc" />
          </div>
          <div className="me-text">
            <div className="me-name">{status?.device.name ?? "…"}</div>
            {status && (
              <div className={`server ${status.server}`}>
                <span className="dot" />
                {t(`server.${status.server}`)}
              </div>
            )}
          </div>
        </div>
        <ul>
          {NAV.map((n) => (
            <li key={n.id}>
              <button
                type="button"
                className={`nav-item ${page === n.id ? "active" : ""}`}
                aria-current={page === n.id ? "page" : undefined}
                onClick={() => setPage(n.id)}
              >
                <Icon name={n.icon} />
                <span>{t(n.label)}</span>
              </button>
            </li>
          ))}
        </ul>
        {status && <div className="version">{t("status.version", { v: status.version })}</div>}
      </nav>
      <main className="content">
        {lost && <div className="banner info">{t("agent.lost")}</div>}
        {fork && (
          <div className="banner danger" role="alert">
            <Icon name="shield" />
            <div className="banner-text">
              <strong>{t("alert.fork.title")}</strong>
              <span>{t("alert.fork.body")}</span>
            </div>
            <div className="banner-actions">
              <button type="button" className="btn" onClick={() => setPage("pairing")}>
                {t("alert.fork.action")}
              </button>
            </div>
          </div>
        )}
        {alerts.map((a) => (
          <div className="banner warning" role="alert" key={a.id}>
            <Icon name="shield" />
            <div className="banner-text">
              <strong>{t("alert.added.title")}</strong>
              <span>{t("alert.added.body", { by: a.by_name, name: a.name, platform: platformName(a.platform) })}</span>
            </div>
            <div className="banner-actions">
              <button type="button" className="btn danger" disabled={alertBusy} onClick={() => void notMe(a)}>
                {t("alert.notMe")}
              </button>
              <button type="button" className="btn" onClick={() => setAlerts((xs) => xs.filter((x) => x.id !== a.id))}>
                {t("alert.ok")}
              </button>
            </div>
          </div>
        ))}
        <div className="page active-transfers">
          <ActiveTransfers />
        </div>
        {page === "pairing" && <PairingPage pairing={pairing} />}
        {page === "devices" && <DevicesPage />}
        {page === "settings" && <SettingsPage />}
        {page === "history" && <HistoryPage />}
      </main>
    </div>
  );
}
