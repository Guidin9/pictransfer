import { useCallback, useEffect, useState } from "react";
import { errorCode, onAgentEvent, rpc, type Device, type RemoveReason } from "../agent";
import { Card, Dialog, Icon } from "../components/ui";
import { platformName, relativeTime, t } from "../i18n";

const MAX_NAME = 64;

export function DevicesPage() {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [removing, setRemoving] = useState<Device | null>(null);

  const load = useCallback(async () => {
    try {
      setDevices(await rpc("devices.list"));
      setError(null);
    } catch (e) {
      setError(errorCode(e));
    }
  }, []);

  useEffect(() => {
    void load();
    return onAgentEvent((e) => {
      if (e.event === "status" || e.event === "pair.done" || e.event === "group.alert") void load();
    });
  }, [load]);

  const act = async (f: () => Promise<unknown>) => {
    try {
      await f();
      await load();
    } catch (e) {
      setError(errorCode(e));
    }
  };

  const sorted = devices ? [...devices].sort((a, b) => Number(b.me) - Number(a.me) || a.name.localeCompare(b.name)) : null;

  return (
    <div className="page">
      <h1>{t("devices.title")}</h1>
      {error && <div className="banner danger">{t("common.error", { code: error })}</div>}
      {!sorted && !error && <p className="muted">{t("common.loading")}</p>}
      {sorted && (
        <Card>
          {sorted.map((d) => (
            <div className="row device" key={d.id}>
              <div className="row-icon">
                <Icon name={d.platform === "android" ? "phone" : "pc"} />
              </div>
              <div className="row-text">
                {renaming === d.id ? (
                  <RenameForm
                    initial={d.name}
                    onCancel={() => setRenaming(null)}
                    onSave={(name) =>
                      void act(async () => {
                        await rpc("devices.rename", { name });
                        setRenaming(null);
                      })
                    }
                  />
                ) : (
                  <div className="row-title">
                    {d.name}
                    {d.me && <span className="badge">{t("devices.me")}</span>}
                    {d.default_target && <span className="badge accent">{t("devices.default")}</span>}
                  </div>
                )}
                <div className="row-desc">
                  {platformName(d.platform)}
                  {!d.me && (
                    <>
                      {" · "}
                      <span className={`presence ${d.online ? "online" : ""}`}>
                        <span className="dot" />
                        {d.online
                          ? t("devices.online")
                          : d.last_seen
                            ? t("devices.offline", { when: relativeTime(d.last_seen) })
                            : t("devices.never")}
                      </span>
                    </>
                  )}
                </div>
              </div>
              <div className="row-control">
                {d.me && renaming !== d.id && (
                  <button type="button" className="btn subtle" onClick={() => setRenaming(d.id)}>
                    <Icon name="pencil" />
                    {t("devices.rename")}
                  </button>
                )}
                {!d.me && !d.default_target && (
                  <button type="button" className="btn subtle" onClick={() => void act(() => rpc("devices.set_default", { id: d.id }))}>
                    <Icon name="target" />
                    {t("devices.setDefault")}
                  </button>
                )}
                {!d.me && (
                  <button type="button" className="btn subtle danger-text" onClick={() => setRemoving(d)}>
                    <Icon name="trash" />
                    {t("common.remove")}
                  </button>
                )}
              </div>
            </div>
          ))}
          {sorted.filter((d) => !d.me).length === 0 && <div className="row muted">{t("devices.empty")}</div>}
        </Card>
      )}
      {removing && (
        <RemoveDialog
          device={removing}
          onCancel={() => setRemoving(null)}
          onRemove={(reason) =>
            void act(async () => {
              await rpc("devices.remove", { id: removing.id, reason });
              setRemoving(null);
            })
          }
        />
      )}
    </div>
  );
}

function RenameForm(props: { initial: string; onSave: (name: string) => void; onCancel: () => void }) {
  const [name, setName] = useState(props.initial);
  const trimmed = name.trim();
  return (
    <form
      className="rename"
      onSubmit={(e) => {
        e.preventDefault();
        if (trimmed) props.onSave(trimmed);
      }}
    >
      <input
        className="input"
        value={name}
        maxLength={MAX_NAME}
        autoFocus
        aria-label={t("devices.name.placeholder")}
        placeholder={t("devices.name.placeholder")}
        onChange={(e) => setName(e.target.value)}
        onKeyDown={(e) => e.key === "Escape" && props.onCancel()}
      />
      <button type="submit" className="btn accent" disabled={!trimmed}>
        {t("common.save")}
      </button>
      <button type="button" className="btn" onClick={props.onCancel}>
        {t("common.cancel")}
      </button>
    </form>
  );
}

function RemoveDialog(props: { device: Device; onRemove: (r: RemoveReason) => void; onCancel: () => void }) {
  const [reason, setReason] = useState<RemoveReason>("user");
  return (
    <Dialog
      title={t("devices.remove.title", { name: props.device.name })}
      onClose={props.onCancel}
      actions={
        <>
          <button type="button" className="btn danger" onClick={() => props.onRemove(reason)}>
            {t("common.remove")}
          </button>
          <button type="button" className="btn" onClick={props.onCancel}>
            {t("common.cancel")}
          </button>
        </>
      }
    >
      <p>{t("devices.remove.body")}</p>
      <fieldset className="radios">
        <legend>{t("devices.remove.reason")}</legend>
        {(["user", "lost-or-stolen"] as const).map((r) => (
          <label key={r}>
            <input type="radio" name="reason" checked={reason === r} onChange={() => setReason(r)} />
            {t(`devices.reason.${r}`)}
          </label>
        ))}
      </fieldset>
    </Dialog>
  );
}
