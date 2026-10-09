import { useCallback, useEffect, useRef, useState } from "react";
import { errorCode, rpc, type Device, type HotkeyCheck, type Settings } from "../agent";
import { Card, Icon, Row, Toggle } from "../components/ui";
import { t } from "../i18n";

const CODE_NAMES: Record<string, string> = {
  Space: "Space",
  Enter: "Enter",
  Tab: "Tab",
  Backspace: "Backspace",
  Insert: "Insert",
  Delete: "Delete",
  Home: "Home",
  End: "End",
  PageUp: "PageUp",
  PageDown: "PageDown",
  ArrowUp: "Up",
  ArrowDown: "Down",
  ArrowLeft: "Left",
  ArrowRight: "Right",
  PrintScreen: "PrintScreen",
  Pause: "Pause",
  Backquote: "`",
  Minus: "-",
  Equal: "=",
  BracketLeft: "[",
  BracketRight: "]",
  Backslash: "\\",
  Semicolon: ";",
  Quote: "'",
  Comma: ",",
  Period: ".",
  Slash: "/",
  IntlBackslash: "<",
};

const MODIFIER_CODES = new Set([
  "ControlLeft", "ControlRight", "AltLeft", "AltRight", "ShiftLeft", "ShiftRight", "MetaLeft", "MetaRight", "OSLeft", "OSRight",
]);

/** Layout-independent key name from `KeyboardEvent.code`, or null. */
export function keyName(code: string): string | null {
  let m = /^Key([A-Z])$/.exec(code);
  if (m?.[1]) return m[1];
  m = /^Digit([0-9])$/.exec(code);
  if (m?.[1]) return m[1];
  m = /^F([0-9]{1,2})$/.exec(code);
  if (m?.[1] && Number(m[1]) >= 1 && Number(m[1]) <= 24) return `F${m[1]}`;
  m = /^Numpad([0-9])$/.exec(code);
  if (m?.[1]) return `Num${m[1]}`;
  return CODE_NAMES[code] ?? null;
}

export function comboFromEvent(e: KeyboardEvent): string | null {
  if (MODIFIER_CODES.has(e.code)) return null;
  const key = keyName(e.code);
  if (!key) return null;
  const parts: string[] = [];
  if (e.ctrlKey) parts.push("Ctrl");
  if (e.altKey) parts.push("Alt");
  if (e.shiftKey) parts.push("Shift");
  if (e.metaKey) parts.push("Win");
  parts.push(key);
  return parts.join("+");
}

function HotkeyRecorder(props: { value: string; onSave: (hk: string) => Promise<void> }) {
  const [recording, setRecording] = useState(false);
  const [pending, setPending] = useState<{ hotkey: string; check: HotkeyCheck } | null>(null);
  const [invalid, setInvalid] = useState(false);
  const saveRef = useRef(props.onSave);
  saveRef.current = props.onSave;

  useEffect(() => {
    if (!recording) return;
    const onKey = (e: KeyboardEvent) => {
      e.preventDefault();
      e.stopPropagation();
      if (e.code === "Escape" && !e.ctrlKey && !e.altKey && !e.shiftKey) {
        setRecording(false);
        return;
      }
      const combo = comboFromEvent(e);
      if (!combo) return;
      setRecording(false);
      void (async () => {
        try {
          const check = await rpc("hotkey.check", { hotkey: combo });
          if (!check.valid) {
            setInvalid(true);
            setPending(null);
          } else if (check.conflict) {
            setInvalid(false);
            setPending({ hotkey: combo, check });
          } else {
            setInvalid(false);
            setPending(null);
            await saveRef.current(combo);
          }
        } catch {
          setInvalid(true);
        }
      })();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [recording]);

  return (
    <div className="hotkey">
      <div className="hotkey-line">
        <div className={`keys ${recording ? "recording" : ""}`} aria-live="polite">
          {recording ? (
            <span className="muted">{t("settings.hotkey.recording")}</span>
          ) : (
            props.value.split("+").map((k) => <kbd key={k}>{k}</kbd>)
          )}
        </div>
        <button
          type="button"
          className="btn"
          onClick={() => {
            setInvalid(false);
            setPending(null);
            setRecording((r) => !r);
          }}
        >
          {recording ? t("common.cancel") : t("settings.hotkey.record")}
        </button>
      </div>
      {invalid && <div className="inline-msg danger">{t("settings.hotkey.invalid")}</div>}
      {pending && (
        <div className="inline-msg warning">
          <div>
            <span className="keys small">
              {pending.hotkey.split("+").map((k) => (
                <kbd key={k}>{k}</kbd>
              ))}
            </span>{" "}
            {pending.check.produces
              ? t("settings.hotkey.conflict", { ch: pending.check.produces })
              : t("settings.hotkey.conflictNoChar")}
          </div>
          <div className="actions">
            <button
              type="button"
              className="btn"
              onClick={() => {
                const hk = pending.hotkey;
                setPending(null);
                void props.onSave(hk);
              }}
            >
              {t("settings.hotkey.useAnyway")}
            </button>
            <button type="button" className="btn accent" onClick={() => setPending(null)}>
              {t("common.cancel")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function NumberField(props: { value: number; min: number; max: number; label: string; onSave: (v: number) => void; suffix?: string }) {
  const [text, setText] = useState(String(props.value));
  useEffect(() => setText(String(props.value)), [props.value]);
  const commit = () => {
    const n = Math.round(Number(text));
    if (Number.isFinite(n) && n >= props.min && n <= props.max) {
      if (n !== props.value) props.onSave(n);
    } else setText(String(props.value));
  };
  return (
    <span className="number-field">
      <input
        className="input num"
        inputMode="numeric"
        aria-label={props.label}
        value={text}
        onChange={(e) => setText(e.target.value.replace(/[^0-9]/g, ""))}
        onBlur={commit}
        onKeyDown={(e) => e.key === "Enter" && commit()}
      />
      {props.suffix && <span className="suffix">{props.suffix}</span>}
    </span>
  );
}

export function SettingsPage() {
  const [s, setS] = useState<Settings | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [saveDir, setSaveDir] = useState("");
  const savedTimer = useRef<number | undefined>(undefined);

  useEffect(() => {
    void (async () => {
      try {
        const [settings, devs] = await Promise.all([rpc("settings.get"), rpc("devices.list")]);
        setS(settings);
        setSaveDir(settings.save_dir);
        setDevices(devs);
      } catch (e) {
        setError(errorCode(e));
      }
    })();
    return () => window.clearTimeout(savedTimer.current);
  }, []);

  const save = useCallback(async (patch: Partial<Settings>) => {
    try {
      const next = await rpc("settings.set", patch);
      setS(next);
      setSaveDir(next.save_dir);
      setError(null);
      setSaved(true);
      window.clearTimeout(savedTimer.current);
      savedTimer.current = window.setTimeout(() => setSaved(false), 1500);
    } catch (e) {
      setError(errorCode(e));
    }
  }, []);

  if (!s) {
    return (
      <div className="page">
        <h1>{t("settings.title")}</h1>
        {error ? <div className="banner danger">{t("common.error", { code: error })}</div> : <p className="muted">{t("common.loading")}</p>}
      </div>
    );
  }

  const targets = devices.filter((d) => !d.me);
  const onReceive = (k: keyof Settings["on_receive"], v: boolean) => void save({ on_receive: { ...s.on_receive, [k]: v } });

  return (
    <div className="page">
      <h1>
        {t("settings.title")}
        <span className={`saved ${saved ? "show" : ""}`} aria-live="polite">
          <Icon name="check" />
          {t("settings.saved")}
        </span>
      </h1>
      {error && <div className="banner danger">{t("common.error", { code: error })}</div>}

      <Card>
        <Row icon={<Icon name="keyboard" />} title={t("settings.hotkey")} desc={t("settings.hotkey.desc")} className="tall">
          <HotkeyRecorder value={s.hotkey} onSave={(hotkey) => save({ hotkey })} />
        </Row>
        <Row icon={<Icon name="target" />} title={t("settings.target")} desc={t("settings.target.desc")}>
          <select
            className="select"
            aria-label={t("settings.target")}
            value={s.default_target ?? ""}
            onChange={(e) => void save({ default_target: e.target.value || null })}
          >
            {targets.length === 0 && <option value="">{t("settings.target.none")}</option>}
            {targets.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
        </Row>
      </Card>

      <h2 className="section">{t("settings.onReceive")}</h2>
      <Card>
        <Row icon={<Icon name="folder" />} title={t("settings.saveDir")} desc={t("settings.saveDir.desc")} className="tall">
          <form
            className="path-field"
            onSubmit={(e) => {
              e.preventDefault();
              const v = saveDir.trim();
              if (v && v !== s.save_dir) void save({ save_dir: v });
            }}
          >
            <input className="input path" aria-label={t("settings.saveDir")} value={saveDir} spellCheck={false} onChange={(e) => setSaveDir(e.target.value)} />
            <button type="submit" className="btn" disabled={!saveDir.trim() || saveDir.trim() === s.save_dir}>
              {t("common.save")}
            </button>
          </form>
        </Row>
        {(["save", "clipboard", "notify", "history"] as const).map((k) => (
          <Row key={k} title={t(`settings.onReceive.${k}`)}>
            <Toggle label={t(`settings.onReceive.${k}`)} checked={s.on_receive[k]} onChange={(v) => onReceive(k, v)} />
          </Row>
        ))}
        <Row title={t("settings.askAbove")}>
          <NumberField label={t("settings.askAbove")} value={s.ask_above_mb} min={1} max={1_000_000} suffix="MB" onSave={(v) => void save({ ask_above_mb: v })} />
        </Row>
      </Card>

      <h2 className="section">{t("settings.general")}</h2>
      <Card>
        <Row title={t("settings.relay")} desc={t("settings.relay.desc")}>
          <Toggle label={t("settings.relay")} checked={s.relay_data} onChange={(v) => void save({ relay_data: v })} />
        </Row>
        <Row title={t("settings.autostart")}>
          <Toggle label={t("settings.autostart")} checked={s.autostart} onChange={(v) => void save({ autostart: v })} />
        </Row>
        <Row title={t("settings.history")}>
          <span className="pair-fields">
            <NumberField label={t("settings.history.days")} value={s.history_days} min={1} max={3650} suffix={t("settings.history.days")} onSave={(v) => void save({ history_days: v })} />
            <NumberField label={t("settings.history.items")} value={s.history_items} min={1} max={10_000} suffix={t("settings.history.items")} onSave={(v) => void save({ history_items: v })} />
          </span>
        </Row>
      </Card>
    </div>
  );
}
