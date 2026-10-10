import { useCallback, useEffect, useState } from "react";
import { errorCode, onAgentEvent, rpc, type HistoryItem } from "../agent";
import { Card, Icon } from "../components/ui";
import { formatSize, locale, t } from "../i18n";

const PAGE = 50;

export function HistoryPage() {
  const [items, setItems] = useState<HistoryItem[] | null>(null);
  const [more, setMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const list = await rpc("history.list", { limit: PAGE });
      setItems(list);
      setMore(list.length === PAGE);
      setError(null);
    } catch (e) {
      setError(errorCode(e));
    }
  }, []);

  useEffect(() => {
    void load();
    return onAgentEvent((e) => {
      if (e.event === "transfer.done") void load();
    });
  }, [load]);

  const loadMore = async () => {
    const last = items?.[items.length - 1];
    if (!last) return;
    try {
      const list = await rpc("history.list", { before: last.ts, limit: PAGE });
      setItems((xs) => [...(xs ?? []), ...list]);
      setMore(list.length === PAGE);
    } catch (e) {
      setError(errorCode(e));
    }
  };

  const act = async (f: () => Promise<unknown>, reload: boolean) => {
    try {
      await f();
      if (reload) await load();
    } catch (e) {
      setError(errorCode(e));
    }
  };

  const fmt = new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" });

  return (
    <div className="page">
      <h1>{t("history.title")}</h1>
      {error && <div className="banner danger">{t("common.error", { code: error })}</div>}
      {!items && !error && <p className="muted">{t("common.loading")}</p>}
      {items && items.length === 0 && (
        <Card>
          <div className="row muted">{t("history.empty")}</div>
        </Card>
      )}
      {items && items.length > 0 && (
        <Card>
          {items.map((h) => (
            <div className={`row history ${h.ok ? "" : "failed"}`} key={h.id}>
              <div className={`row-icon dir-${h.direction}`}>
                <Icon name={h.direction === "in" ? "arrowIn" : "arrowOut"} />
              </div>
              <div className="row-text">
                {/* Names are shown as plain text only; React escapes them. */}
                <div className="row-title" title={h.name}>
                  <span className="row-title-text">{h.name ?? t(`history.kind.${h.kind}`)}</span>
                  {!h.ok && <span className="badge danger">{t("history.failed")}</span>}
                </div>
                <div className="row-desc">
                  {/* Short parts wrap as a whole ("258,4 MB", not "258,4 / MB");
                      the peer sentence may wrap anywhere (long device names). */}
                  {[
                    t(h.direction === "in" ? "history.in" : "history.out", { peer: h.peer }),
                    t(`history.kind.${h.kind}`),
                    formatSize(h.size),
                    fmt.format(h.ts),
                  ].map((part, i) => (
                    <span className={i > 0 ? "desc-part" : undefined} key={i}>
                      {i > 0 && " · "}
                      {part}
                    </span>
                  ))}
                </div>
              </div>
              <div className="row-control">
                {h.path && h.ok && (
                  <button
                    type="button"
                    className="btn subtle reveal"
                    title={t("history.reveal")}
                    aria-label={t("history.reveal")}
                    onClick={() => void act(() => rpc("history.reveal", { id: h.id }), false)}
                  >
                    <Icon name="folder" />
                    <span className="btn-label">{t("history.reveal")}</span>
                  </button>
                )}
                <button
                  type="button"
                  className="btn subtle icon-only"
                  title={t("history.delete")}
                  aria-label={t("history.delete")}
                  onClick={() => void act(() => rpc("history.delete", { id: h.id }), true)}
                >
                  <Icon name="trash" />
                </button>
              </div>
            </div>
          ))}
        </Card>
      )}
      {more && (
        <button type="button" className="btn more" onClick={() => void loadMore()}>
          {t("history.more")}
        </button>
      )}
    </div>
  );
}
