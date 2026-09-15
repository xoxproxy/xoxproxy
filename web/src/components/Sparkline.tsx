// Sparkline: a tiny inline area chart for stat cards. Pure SVG — no
// chart-library overhead at this size.

export default function Sparkline({ data, tone = "brand" }: {
  data: number[];
  tone?: "brand" | "success" | "error";
}) {
  if (data.length < 2) return null;

  const W = 96;
  const H = 28;
  const PAD = 2;
  const max = Math.max(...data, 1);

  const points = data.map((v, i) => {
    const x = PAD + (i / (data.length - 1)) * (W - 2 * PAD);
    const y = H - PAD - (v / max) * (H - 2 * PAD);
    return [x, y] as const;
  });

  const line = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `${PAD},${H - PAD} ${line} ${W - PAD},${H - PAD}`;

  const stroke = {
    brand: "var(--brand-primary)",
    success: "var(--success-500)",
    error: "var(--error-500)",
  }[tone];
  const fill = {
    brand: "var(--brand-100)",
    success: "var(--success-100)",
    error: "var(--error-100)",
  }[tone];

  return (
    <svg
      width={W}
      height={H}
      viewBox={`0 0 ${W} ${H}`}
      aria-hidden
      className="shrink-0"
    >
      <polygon points={area} fill={fill} />
      <polyline
        points={line}
        fill="none"
        stroke={stroke}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}
