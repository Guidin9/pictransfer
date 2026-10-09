import { useEffect, useRef, type ReactNode } from "react";
import { encodeQr } from "../qr";

export function Toggle(props: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={props.checked}
      aria-label={props.label}
      className={`toggle ${props.checked ? "on" : ""}`}
      disabled={props.disabled}
      onClick={() => props.onChange(!props.checked)}
    >
      <span className="knob" />
    </button>
  );
}

export function Row(props: { title: string; desc?: string; icon?: ReactNode; children?: ReactNode; className?: string }) {
  return (
    <div className={`row ${props.className ?? ""}`}>
      {props.icon && <div className="row-icon">{props.icon}</div>}
      <div className="row-text">
        <div className="row-title">{props.title}</div>
        {props.desc && <div className="row-desc">{props.desc}</div>}
      </div>
      {props.children && <div className="row-control">{props.children}</div>}
    </div>
  );
}

export function Card(props: { children: ReactNode; className?: string }) {
  return <section className={`card ${props.className ?? ""}`}>{props.children}</section>;
}

export function Dialog(props: { title: string; children: ReactNode; actions: ReactNode; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const onClose = useRef(props.onClose);
  onClose.current = props.onClose;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose.current();
    };
    window.addEventListener("keydown", onKey);
    ref.current?.querySelector<HTMLElement>("input, button")?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <div className="scrim" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <div className="dialog" role="dialog" aria-modal="true" aria-label={props.title} ref={ref}>
        <h2>{props.title}</h2>
        <div className="dialog-body">{props.children}</div>
        <div className="dialog-actions">{props.actions}</div>
      </div>
    </div>
  );
}

/** QR code as inline SVG (no data: URLs, no network). Always dark on light. */
export function QrCode(props: { text: string; label: string; size?: number }) {
  const qr = encodeQr(props.text, "M");
  const quiet = 4;
  const dim = qr.size + quiet * 2;
  // Whole CSS pixels per module keeps modules evenly sized.
  const px = dim * Math.max(3, Math.floor((props.size ?? 280) / dim));
  let d = "";
  qr.modules.forEach((row, y) => {
    row.forEach((dark, x) => {
      if (dark) d += `M${x + quiet} ${y + quiet}h1v1h-1z`;
    });
  });
  return (
    <svg
      className="qr"
      role="img"
      aria-label={props.label}
      viewBox={`0 0 ${dim} ${dim}`}
      width={px}
      height={px}
      shapeRendering="crispEdges"
      data-version={qr.version}
      data-mode={qr.alnum ? "alphanumeric" : "byte"}
    >
      <rect width={dim} height={dim} fill="#fff" />
      <path d={d} fill="#000" />
    </svg>
  );
}

export function Icon(props: { name: keyof typeof ICONS; className?: string }) {
  return (
    <svg className={`icon ${props.className ?? ""}`} viewBox="0 0 24 24" aria-hidden="true">
      <path d={ICONS[props.name]} />
    </svg>
  );
}

// Simple outline glyphs drawn for this app (Fluent-like, 24px grid).
const ICONS = {
  pair: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM18 14h2v2h-2zM14 18h2v2h-2zM18 18h2v2h-2zM6 6v2h2V6zM16 6v2h2V6zM6 16v2h2v-2z",
  devices: "M3 5.5A1.5 1.5 0 0 1 4.5 4h11A1.5 1.5 0 0 1 17 5.5V7h-1.5V5.5h-11v8h8V15H11v1.5h1.5V18H6v-1.5h3.5V15h-5A1.5 1.5 0 0 1 3 13.5zM15.5 9h4A1.5 1.5 0 0 1 21 10.5v8a1.5 1.5 0 0 1-1.5 1.5h-4a1.5 1.5 0 0 1-1.5-1.5v-8A1.5 1.5 0 0 1 15.5 9zm0 1.5v8h4v-8z",
  settings: "M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7zm0 1.5a2 2 0 1 1 0 4 2 2 0 0 1 0-4zM10.6 2h2.8l.5 2.6c.6.2 1.2.5 1.7.9l2.5-.9 1.4 2.4-2 1.7a7 7 0 0 1 0 2.6l2 1.7-1.4 2.4-2.5-.9c-.5.4-1.1.7-1.7.9l-.5 2.6h-2.8l-.5-2.6c-.6-.2-1.2-.5-1.7-.9l-2.5.9-1.4-2.4 2-1.7a7 7 0 0 1 0-2.6l-2-1.7 1.4-2.4 2.5.9c.5-.4 1.1-.7 1.7-.9zm1.2 1.5-.4 2.2-.8.3a5.5 5.5 0 0 0-1.9 1.1l-.6.5-2.1-.8-.3.6 1.7 1.4-.2.8a5.5 5.5 0 0 0 0 2.2l.2.8-1.7 1.4.3.6 2.1-.8.6.5c.6.5 1.2.9 1.9 1.1l.8.3.4 2.2h.6l.4-2.2.8-.3c.7-.2 1.3-.6 1.9-1.1l.6-.5 2.1.8.3-.6-1.7-1.4.2-.8a5.5 5.5 0 0 0 0-2.2l-.2-.8 1.7-1.4-.3-.6-2.1.8-.6-.5a5.5 5.5 0 0 0-1.9-1.1l-.8-.3-.4-2.2z",
  history: "M12 3a9 9 0 1 1-8.5 6h1.6A7.5 7.5 0 1 0 6.7 6.7L9 9H3V3l2.6 2.6A9 9 0 0 1 12 3zm-.75 4h1.5v4.7l3.3 2-.8 1.3-4-2.4z",
  phone: "M8 2h8a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zm0 1.5a.5.5 0 0 0-.5.5v16c0 .3.2.5.5.5h8c.3 0 .5-.2.5-.5V4a.5.5 0 0 0-.5-.5zM10.5 17h3v1.5h-3z",
  pc: "M3 5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2h-5.5v2.5H17V21H7v-1.5h3.5V17H5a2 2 0 0 1-2-2zm2-.5a.5.5 0 0 0-.5.5v10c0 .3.2.5.5.5h14c.3 0 .5-.2.5-.5V5a.5.5 0 0 0-.5-.5z",
  folder: "M3 6.5A2.5 2.5 0 0 1 5.5 4h3.6l2 2h7.4A2.5 2.5 0 0 1 21 8.5v9a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5zm2.5-1a1 1 0 0 0-1 1v11c0 .6.4 1 1 1h13c.6 0 1-.4 1-1v-9c0-.6-.4-1-1-1h-8l-2-2z",
  keyboard: "M2 7a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2zm2-.5a.5.5 0 0 0-.5.5v10c0 .3.2.5.5.5h16c.3 0 .5-.2.5-.5V7a.5.5 0 0 0-.5-.5zM6 9h2v2H6zm3.5 0h2v2h-2zM13 9h2v2h-2zm3.5 0h2v2h-2zM6 12.5h2v2H6zm11 0h1.5v2H17zM9.5 12.5h6v2h-6z",
  target: "M12 2a10 10 0 1 1 0 20 10 10 0 0 1 0-20zm0 1.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17zM12 6a6 6 0 1 1 0 12 6 6 0 0 1 0-12zm0 1.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zM12 10a2 2 0 1 1 0 4 2 2 0 0 1 0-4z",
  shield: "M12 2 20 5v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5zm0 1.6L5.5 6v5c0 4.1 2.7 7.8 6.5 9.4 3.8-1.6 6.5-5.3 6.5-9.4V6zM11.25 7h1.5v6h-1.5zm0 7.5h1.5V16h-1.5z",
  arrowIn: "M12 3v11.2l4.2-4.2 1.1 1.1-6 6-6-6 1.1-1.1 4.1 4.2V3zM4 19.5h16V21H4z",
  arrowOut: "M12 21V9.8l4.2 4.2 1.1-1.1-6-6-6 6 1.1 1.1 4.1-4.2V21zM4 3h16v1.5H4z",
  check: "M9 16.2 4.8 12l-1.1 1.1L9 18.4 20.3 7.1 19.2 6z",
  close: "M6.1 5 12 10.9 17.9 5 19 6.1 13.1 12 19 17.9 17.9 19 12 13.1 6.1 19 5 17.9 10.9 12 5 6.1z",
  plug: "M8 2h1.5v5h5V2H16v5h1.5v4.5A5.5 5.5 0 0 1 12.75 17v5h-1.5v-5a5.5 5.5 0 0 1-4.75-5.5V7H8zm0 6.5v3a4 4 0 0 0 8 0v-3z",
  pencil: "M16.6 3.4a2 2 0 0 1 2.8 0l1.2 1.2a2 2 0 0 1 0 2.8L8.3 19.7 3 21l1.3-5.3zm1.8 1.1a.5.5 0 0 0-.7 0L15.9 6.3l1.8 1.8 1.8-1.8a.5.5 0 0 0 0-.7zM14.8 7.4 5.6 16.6l-.6 2.4 2.4-.6 9.2-9.2z",
  trash: "M9 3h6l.5 1.5H20V6H4V4.5h4.5zM5.5 7.5H7l.9 12h8.2l.9-12h1.5l-1 13.5H6.5z",
} as const;
