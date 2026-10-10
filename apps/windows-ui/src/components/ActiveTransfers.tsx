import { Fragment, useEffect, useState } from "react";
import { errorCode, onAgentEvent, rpc, type Transfer } from "../agent";
import { formatDuration, formatSize, locale, t } from "../i18n";
import { Card, Icon } from "./ui";

/**
 * Running sends and receives with progress and Cancel (roadmap 3 + 4b). Shown
 * only while something runs; the agent is the source of truth (`transfer.list`
 * on mount, then `transfer.*` events).
 */
export function ActiveTransfers() {
  const [list, setList] = useState<Transfer[]>([]);
  const [cancelling, setCancelling] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const off = onAgentEvent((e) => {
      if (e.event === "transfer.started") {
        setList((xs) => [...xs.filter((x) => x.transfer !== e.data.transfer), e.data]);
      } else if (e.event === "transfer.progress") {
        setList((xs) => xs.map((x) => (x.transfer === e.data.transfer ? { ...x, ...e.data, state: "running" } : x)));
      } else if (e.event === "transfer.done") {
        setList((xs) => xs.filter((x) => x.transfer !== e.data.transfer));
      }
    });
    rpc("transfer.list")
      .then((r) => alive && setList(r.transfers))
      .catch(() => {});
    return () => {
      alive = false;
      off();
    };
  }, []);

  if (list.length === 0) return null;

  const cancel = async (id: string) => {
    setCancelling((s) => new Set(s).add(id));
    try {
      await rpc("transfer.cancel", { transfer: id });
      setError(null);
    } catch (e) {
      // `not-found`: it ended meanwhile; the `transfer.done` event removes it.
      if (errorCode(e) !== "not-found") setError(errorCode(e));
    }
  };

  const pctFmt = new Intl.NumberFormat(locale, { style: "percent", maximumFractionDigits: 0 });

  return (
    <>
      <h2 className="section">{t("transfers.title")}</h2>
      {error && <div className="banner danger">{t("common.error", { code: error })}</div>}
      <Card className="transfers">
        {list.map((x) => {
          const running = x.state === "running" && x.total_bytes > 0;
          const frac = running ? Math.min(1, x.done_bytes / x.total_bytes) : 0;
          const left = running && x.bytes_per_sec > 0 ? (x.total_bytes - x.done_bytes) / x.bytes_per_sec : null;
          const title =
            x.label ||
            (x.items > 1
              ? t("transfers.items", { n: x.items })
              : t(x.direction === "in" ? "transfers.incoming" : "history.kind.text"));
          const parts = [
            t(x.direction === "in" ? "transfers.in" : "transfers.out", { peer: x.peer }),
            ...(running
              ? [
                  pctFmt.format(frac),
                  `${formatSize(x.done_bytes)} / ${formatSize(x.total_bytes)}`,
                  ...(x.bytes_per_sec > 0 ? [t("transfers.rate", { rate: formatSize(x.bytes_per_sec) })] : []),
                  ...(left !== null && frac < 1 ? [t("transfers.left", { time: formatDuration(left) })] : []),
                ]
              : [t(x.state === "waiting" ? "transfers.waiting" : "transfers.starting")]),
          ];
          const busy = cancelling.has(x.transfer);
          return (
            <div className="row transfer" key={x.transfer}>
              <div className={`row-icon dir-${x.direction}`}>
                <Icon name={x.direction === "in" ? "arrowIn" : "arrowOut"} />
              </div>
              <div className="row-text">
                <div className="row-title" title={title}>
                  <span className="row-title-text">{title}</span>
                </div>
                <div className="row-desc">
                  {parts.map((part, i) => (
                    <Fragment key={i}>
                      {/* The separator stays outside the no-wrap part: lines break between parts. */}
                      {i > 0 && " · "}
                      <span className={i > 0 ? "desc-part" : undefined}>{part}</span>
                    </Fragment>
                  ))}
                </div>
                <div
                  className={`progress ${running ? "" : "indeterminate"}`}
                  role="progressbar"
                  aria-label={title}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={running ? Math.round(frac * 100) : undefined}
                >
                  <div style={running ? { width: `${frac * 100}%` } : undefined} />
                </div>
              </div>
              <div className="row-control">
                <button type="button" className="btn" disabled={busy} onClick={() => void cancel(x.transfer)}>
                  <Icon name="close" />
                  <span>{busy ? t("transfers.cancelling") : t("common.cancel")}</span>
                </button>
              </div>
            </div>
          );
        })}
      </Card>
    </>
  );
}
