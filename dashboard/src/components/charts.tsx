import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { fmtInt } from "../lib/format";
import type { Contribution, Verdict } from "../lib/types";

// Everything here is plain SVG. It's a handful of chart shapes and none of them
// need a charting library, which keeps the bundle small and the look consistent.

function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    setWidth(el.clientWidth);
    const ro = new ResizeObserver(([entry]) => setWidth(Math.floor(entry.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, width];
}

// Flips on one frame after mount so CSS transitions have something to animate from.
function useMounted() {
  const [on, setOn] = useState(false);
  useEffect(() => { const id = requestAnimationFrame(() => setOn(true)); return () => cancelAnimationFrame(id); }, []);
  return on;
}

const linear = (d0: number, d1: number, r0: number, r1: number) => (v: number) => r0 + ((v - d0) / (d1 - d0 || 1)) * (r1 - r0);

// Picks an axis maximum and tick values that land on round numbers.
function niceScale(v: number, count = 4): { max: number; ticks: number[] } {
  if (v <= 0) return { max: 1, ticks: [0, 1] };
  const raw = v / count;
  const pow = Math.pow(10, Math.floor(Math.log10(raw)));
  const n = raw / pow;
  const step = (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * pow;
  const steps = Math.ceil(v / step);
  return { max: step * steps, ticks: Array.from({ length: steps + 1 }, (_, i) => step * i) };
}
const niceMax = (v: number) => niceScale(v).max;

// ---------------------------------------------------------------------------
// Verdict ring: the big animated gauge on a case page.

export function ScoreRing({ score, verdict, thresholds, size = 168, label }: {
  score: number; verdict: Verdict; thresholds?: { suspicious: number; malicious: number }; size?: number; label?: string;
}) {
  const mounted = useMounted();
  const id = useId().replace(/:/g, "");
  const stroke = 11;
  const r = (size - stroke) / 2 - 4;
  const c = 2 * Math.PI * r;
  const sweep = 0.78; // leave a gap at the bottom, like an instrument dial
  const start = 90 + (360 * (1 - sweep)) / 2;
  const arc = c * sweep;
  const filled = arc * Math.min(1, Math.max(0, score));
  const tick = (t: number) => {
    const a = ((start + 360 * sweep * t) * Math.PI) / 180;
    const cx = size / 2, cy = size / 2;
    return { x1: cx + (r - 9) * Math.cos(a), y1: cy + (r - 9) * Math.sin(a), x2: cx + (r + 9) * Math.cos(a), y2: cy + (r + 9) * Math.sin(a) };
  };
  return (
    <div className="score-ring" data-v={verdict} style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Score ${score.toFixed(2)}, ${verdict}`}>
        <defs>
          <linearGradient id={`${id}-g`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="var(--v)" stopOpacity="0.55" />
            <stop offset="1" stopColor="var(--v)" />
          </linearGradient>
          <filter id={`${id}-glow`} x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="5" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>
        <g transform={`rotate(${start} ${size / 2} ${size / 2})`}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--line)" strokeWidth={stroke} strokeLinecap="round" strokeDasharray={`${arc} ${c}`} />
          <circle
            cx={size / 2} cy={size / 2} r={r} fill="none" stroke={`url(#${id}-g)`} strokeWidth={stroke} strokeLinecap="round"
            strokeDasharray={`${mounted ? filled : 0} ${c}`} filter={`url(#${id}-glow)`}
            style={{ transition: "stroke-dasharray 1.1s var(--ease)" }}
          />
        </g>
        {thresholds && [thresholds.suspicious, thresholds.malicious].map((t) => (
          <line key={t} {...tick(t)} stroke="var(--text-faint)" strokeWidth="1.5" strokeLinecap="round" opacity="0.7" />
        ))}
      </svg>
      <div className="score-ring-center">
        <strong>{score.toFixed(2)}</strong>
        <span>{label ?? "risk score"}</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Donut for the verdict mix.

export function Donut({ segments, size = 150, thickness = 16, children }: {
  segments: { label: string; value: number; color: string }[]; size?: number; thickness?: number; children?: ReactNode;
}) {
  const mounted = useMounted();
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const gap = segments.filter((s) => s.value > 0).length > 1 ? 4 : 0;
  let offset = 0;
  return (
    <div className="donut" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={segments.map((s) => `${s.label}: ${s.value}`).join(", ")}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--line)" strokeWidth={thickness} />
        <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
          {segments.map((s) => {
            const len = (s.value / total) * c;
            const el = (
              <circle key={s.label} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={s.color} strokeWidth={thickness} strokeLinecap="butt"
                strokeDasharray={`${mounted ? Math.max(0, len - gap) : 0} ${c}`} strokeDashoffset={-offset}
                style={{ transition: "stroke-dasharray 1s var(--ease)" }} />
            );
            offset += len;
            return el;
          })}
        </g>
      </svg>
      <div className="donut-center">{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sparkline for KPI cards.

export function Spark({ values, color = "var(--accent)", height = 36 }: { values: number[]; color?: string; height?: number }) {
  const id = useId().replace(/:/g, "");
  const [ref, width] = useWidth<HTMLDivElement>();
  const path = useMemo(() => {
    if (values.length < 2 || !width) return null;
    const max = Math.max(...values, 1);
    const x = linear(0, values.length - 1, 1, width - 1);
    const y = linear(0, max, height - 3, 3);
    const pts = values.map((v, i) => [x(i), y(v)] as const);
    const line = pts.map(([px, py], i) => `${i ? "L" : "M"}${px.toFixed(1)},${py.toFixed(1)}`).join(" ");
    return { line, area: `${line} L${width - 1},${height} L1,${height} Z` };
  }, [values, width, height]);
  return (
    <div ref={ref} className="spark" style={{ height }}>
      {path && (
        <svg width={width} height={height} aria-hidden="true">
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor={color} stopOpacity="0.35" />
              <stop offset="1" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={path.area} fill={`url(#${id})`} />
          <path d={path.line} fill="none" stroke={color} strokeWidth="1.8" strokeLinejoin="round" strokeLinecap="round" />
        </svg>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Stacked daily columns with a hover readout.

interface Day { date: string; malicious: number; suspicious: number; likely_safe: number }

export function DailyChart({ days, height = 240 }: { days: Day[]; height?: number }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const mounted = useMounted();
  const pad = { l: 34, r: 6, t: 10, b: 24 };
  const { max, ticks } = niceScale(Math.max(...days.map((d) => d.malicious + d.suspicious + d.likely_safe), 1));
  const innerW = Math.max(0, width - pad.l - pad.r);
  const innerH = height - pad.t - pad.b;
  const slot = innerW / Math.max(days.length, 1);
  const barW = Math.min(30, slot * 0.64);
  const y = linear(0, max, innerH, 0);
  const layers: [keyof Day, string][] = [["likely_safe", "var(--ok)"], ["suspicious", "var(--warn)"], ["malicious", "var(--danger)"]];
  const label = (iso: string) => new Date(`${iso}T12:00:00`).toLocaleDateString("en-US", { month: "short", day: "numeric" });

  return (
    <div ref={ref} className="chart" style={{ height }} onMouseLeave={() => setHover(null)}>
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label="Reports per day by verdict">
          <g transform={`translate(${pad.l},${pad.t})`}>
            {ticks.map((t) => (
              <g key={t}>
                <line x1={0} x2={innerW} y1={y(t)} y2={y(t)} stroke="var(--line)" strokeDasharray={t === 0 ? undefined : "2 5"} />
                <text x={-8} y={y(t) + 4} textAnchor="end">{t}</text>
              </g>
            ))}
            {days.map((d, i) => {
              const cx = slot * i + slot / 2;
              let acc = 0;
              return (
                <g key={d.date} onMouseEnter={() => setHover(i)}>
                  <rect x={slot * i} y={0} width={slot} height={innerH} fill={hover === i ? "var(--panel-hover)" : "transparent"} rx={6} />
                  {layers.map(([key, color]) => {
                    const v = d[key] as number;
                    const h = (v / max) * innerH;
                    const top = innerH - ((acc + v) / max) * innerH;
                    acc += v;
                    if (!v) return null;
                    return <rect key={key} x={cx - barW / 2} width={barW} y={mounted ? top : innerH} height={mounted ? Math.max(h - 1.5, 0.5) : 0} rx={3} fill={color}
                      opacity={hover === null || hover === i ? 1 : 0.45} style={{ transition: `y .8s var(--ease) ${i * 25}ms, height .8s var(--ease) ${i * 25}ms, opacity .2s` }} />;
                  })}
                  {(days.length <= 10 || i % 2 === 0) && <text x={cx} y={innerH + 17} textAnchor="middle">{label(d.date)}</text>}
                </g>
              );
            })}
          </g>
        </svg>
      )}
      {hover !== null && days[hover] && (
        <div className="tip" style={{ left: Math.min(Math.max(pad.l + slot * hover + slot / 2, 80), width - 80), top: 6 }}>
          <strong>{label(days[hover].date)}</strong>
          <span><i style={{ background: "var(--danger)" }} />Malicious <b>{days[hover].malicious}</b></span>
          <span><i style={{ background: "var(--warn)" }} />Suspicious <b>{days[hover].suspicious}</b></span>
          <span><i style={{ background: "var(--ok)" }} />Likely safe <b>{days[hover].likely_safe}</b></span>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Line chart for ROC and precision-recall curves.

export function CurveChart({ points, xLabel, yLabel, marker, diagonal = false, height = 280, color = "var(--accent)" }: {
  points: [number, number][]; xLabel: string; yLabel: string; marker?: { x: number; y: number; label: string };
  diagonal?: boolean; height?: number; color?: string;
}) {
  const id = useId().replace(/:/g, "");
  const [ref, width] = useWidth<HTMLDivElement>();
  const pad = { l: 44, r: 12, t: 12, b: 40 };
  const innerW = Math.max(0, width - pad.l - pad.r);
  const innerH = height - pad.t - pad.b;
  const x = linear(0, 1, 0, innerW);
  const y = linear(0, 1, innerH, 0);
  const line = points.map(([px, py], i) => `${i ? "L" : "M"}${x(px).toFixed(1)},${y(py).toFixed(1)}`).join(" ");
  const area = points.length ? `${line} L${x(points[points.length - 1][0]).toFixed(1)},${innerH} L${x(points[0][0]).toFixed(1)},${innerH} Z` : "";
  const grid = [0, 0.25, 0.5, 0.75, 1];
  return (
    <div ref={ref} className="chart" style={{ height }}>
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label={`${yLabel} against ${xLabel}`}>
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor={color} stopOpacity="0.28" />
              <stop offset="1" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>
          <g transform={`translate(${pad.l},${pad.t})`}>
            {grid.map((g) => (
              <g key={g}>
                <line x1={0} x2={innerW} y1={y(g)} y2={y(g)} stroke="var(--line)" strokeDasharray={g === 0 ? undefined : "2 5"} />
                <text x={-8} y={y(g) + 4} textAnchor="end">{g.toFixed(g === 0 || g === 1 ? 0 : 2)}</text>
                <text x={x(g)} y={innerH + 17} textAnchor="middle">{g.toFixed(g === 0 || g === 1 ? 0 : 2)}</text>
              </g>
            ))}
            {diagonal && <line x1={x(0)} y1={y(0)} x2={x(1)} y2={y(1)} stroke="var(--text-faint)" strokeDasharray="4 5" opacity="0.6" />}
            <path d={area} fill={`url(#${id})`} />
            <path d={line} fill="none" stroke={color} strokeWidth="2.2" strokeLinejoin="round" strokeLinecap="round" />
            {marker && (
              <g transform={`translate(${x(marker.x)},${y(marker.y)})`}>
                <circle r="9" fill={color} opacity="0.18" />
                <circle r="4.5" fill="var(--bg)" stroke={color} strokeWidth="2.4" />
                <text x={marker.x > 0.6 ? -12 : 12} y={marker.y > 0.85 ? 18 : -10} textAnchor={marker.x > 0.6 ? "end" : "start"} className="chart-callout">{marker.label}</text>
              </g>
            )}
            <text x={innerW / 2} y={innerH + 34} textAnchor="middle" className="axis-title">{xLabel}</text>
            <text transform={`translate(-34,${innerH / 2}) rotate(-90)`} textAnchor="middle" className="axis-title">{yLabel}</text>
          </g>
        </svg>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Score distributions with the two thresholds drawn on top.

export function ScoreHistogram({ phish, ham, suspicious, malicious, height = 220 }: {
  phish: number[]; ham: number[]; suspicious: number; malicious: number; height?: number;
}) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const bins = 25;
  const counts = useMemo(() => {
    const bucket = (xs: number[]) => {
      const out = new Array(bins).fill(0);
      for (const v of xs) out[Math.min(bins - 1, Math.floor(v * bins))]++;
      return out as number[];
    };
    return { phish: bucket(phish), ham: bucket(ham) };
  }, [phish, ham]);
  const pad = { l: 34, r: 8, t: 14, b: 28 };
  const innerW = Math.max(0, width - pad.l - pad.r);
  const innerH = height - pad.t - pad.b;
  const max = niceMax(Math.max(...counts.phish, ...counts.ham, 1));
  const x = linear(0, 1, 0, innerW);
  const y = linear(0, max, innerH, 0);
  const bw = innerW / bins;
  return (
    <div ref={ref} className="chart" style={{ height }}>
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label="Distribution of test scores for phishing and legitimate mail">
          <g transform={`translate(${pad.l},${pad.t})`}>
            {[0, 0.5, 1].map((t) => (
              <g key={t}>
                <line x1={0} x2={innerW} y1={y(max * t)} y2={y(max * t)} stroke="var(--line)" strokeDasharray={t === 0 ? undefined : "2 5"} />
                <text x={-8} y={y(max * t) + 4} textAnchor="end">{Math.round(max * t)}</text>
              </g>
            ))}
            {counts.ham.map((n, i) => n > 0 && <rect key={`h${i}`} x={i * bw + 1} width={bw - 2} y={y(n)} height={innerH - y(n)} fill="var(--ok)" opacity="0.62" rx="2" />)}
            {counts.phish.map((n, i) => n > 0 && <rect key={`p${i}`} x={i * bw + 1} width={bw - 2} y={y(n)} height={innerH - y(n)} fill="var(--danger)" opacity="0.62" rx="2" />)}
            {[[suspicious, "flag", "var(--warn)"], [malicious, "block", "var(--danger)"]].map(([t, name, color]) => (
              <g key={name as string}>
                <line x1={x(t as number)} x2={x(t as number)} y1={-6} y2={innerH} stroke={color as string} strokeWidth="1.8" strokeDasharray="5 4" />
                <text x={x(t as number)} y={-1} textAnchor={(t as number) > 0.85 ? "end" : "start"} dx={(t as number) > 0.85 ? -5 : 5} className="chart-callout" fill={color as string}>{name as string} {(t as number).toFixed(2)}</text>
              </g>
            ))}
            {[0, 0.25, 0.5, 0.75, 1].map((t) => <text key={t} x={x(t)} y={innerH + 17} textAnchor="middle">{t === 0 || t === 1 ? t : t.toFixed(2)}</text>)}
          </g>
        </svg>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Horizontal bars for "top rules" style lists.

export function BarList({ rows, color = "var(--accent)" }: { rows: { key: string; label: ReactNode; value: number; sub?: string }[]; color?: string }) {
  const mounted = useMounted();
  const max = Math.max(...rows.map((r) => r.value), 1);
  return (
    <ul className="barlist">
      {rows.map((r, i) => (
        <li key={r.key}>
          <div className="barlist-row">
            <span className="barlist-label">{r.label}</span>
            <span className="barlist-value">{fmtInt(r.value)}</span>
          </div>
          <div className="barlist-track">
            <div style={{ width: mounted ? `${(r.value / max) * 100}%` : 0, background: color, transitionDelay: `${i * 45}ms` }} />
          </div>
          {r.sub && <span className="barlist-sub">{r.sub}</span>}
        </li>
      ))}
    </ul>
  );
}

// ---------------------------------------------------------------------------
// Why the model scored what it did: baseline + each feature's push, in log-odds.

export function Waterfall({ baseline, contributions, limit = 9 }: { baseline: number; contributions: Contribution[]; limit?: number }) {
  const mounted = useMounted();
  const shown = [...contributions].filter((c) => Math.abs(c.contribution) > 0.005).sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution)).slice(0, limit);
  const rest = contributions.reduce((s, c) => s + c.contribution, 0) - shown.reduce((s, c) => s + c.contribution, 0);
  const rows = [
    { key: "base", label: "Starting point", note: "log-odds of a typical report", value: baseline, kind: "base" as const },
    ...shown.map((c) => ({ key: c.feature, label: c.label, note: c.value === 1 ? "present" : `value ${+c.value.toFixed(2)}`, value: c.contribution, kind: "feature" as const })),
    ...(Math.abs(rest) > 0.005 ? [{ key: "rest", label: "Everything else", note: "smaller effects combined", value: rest, kind: "feature" as const }] : []),
  ];
  const total = rows.reduce((s, r) => s + r.value, 0);
  let running = 0;
  const spans = rows.map((r) => { const from = running; running += r.value; return [from, running] as const; });
  const lo = Math.min(0, ...spans.flat(), total);
  const hi = Math.max(0, ...spans.flat(), total);
  const pos = (v: number) => ((v - lo) / (hi - lo || 1)) * 100;
  const prob = 1 / (1 + Math.exp(-total));
  return (
    <div className="waterfall" style={{ "--zero": `${pos(0)}%` } as React.CSSProperties}>
      {rows.map((r, i) => {
        const [a, b] = spans[i];
        const left = pos(Math.min(a, b));
        const w = Math.max(0.8, Math.abs(pos(b) - pos(a)));
        return (
          <div key={r.key} className="wf-row" data-kind={r.kind} data-sign={r.value >= 0 ? "up" : "down"}>
            <div className="wf-label"><span>{r.label}</span><small>{r.note}</small></div>
            <div className="wf-track"><div className="wf-bar" style={{ left: `${left}%`, width: mounted ? `${w}%` : 0, transitionDelay: `${i * 55}ms` }} /></div>
            <div className="wf-value">{r.kind === "base" ? r.value.toFixed(2) : `${r.value >= 0 ? "+" : "−"}${Math.abs(r.value).toFixed(2)}`}</div>
          </div>
        );
      })}
      <div className="wf-total">
        <span>Model result</span>
        <b>{total.toFixed(2)} log-odds</b>
        <span className="wf-arrow">→</span>
        <b>{(prob * 100).toFixed(0)}% phishing probability</b>
      </div>
    </div>
  );
}
