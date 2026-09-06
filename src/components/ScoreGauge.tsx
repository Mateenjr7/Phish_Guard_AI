import { useEffect, useState } from "react";

interface ScoreGaugeProps {
  score: number;
  size?: number;
  label?: string;
}

const ScoreGauge = ({ score, size = 120, label = "Scam Risk Score" }: ScoreGaugeProps) => {
  const [animated, setAnimated] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => setAnimated(score), 300);
    return () => clearTimeout(timer);
  }, [score]);

  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const halfCircumference = circumference / 2;
  const offset = halfCircumference - (animated / 100) * halfCircumference;

  const getColor = (val: number) => {
    if (val < 30) return "hsl(160, 60%, 45%)";
    if (val < 60) return "hsl(38, 92%, 50%)";
    return "hsl(0, 72%, 51%)";
  };

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size * 0.65} viewBox="0 0 100 60" className="overflow-visible">
        {/* Background arc */}
        <path
          d="M 5 55 A 45 45 0 0 1 95 55"
          fill="none"
          stroke="hsl(240, 12%, 25%)"
          strokeWidth="8"
          strokeLinecap="round"
        />
        {/* Score arc */}
        <path
          d="M 5 55 A 45 45 0 0 1 95 55"
          fill="none"
          stroke={getColor(animated)}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={`${halfCircumference}`}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1.5s ease-out, stroke 0.5s ease" }}
        />
        {/* Score text */}
        <text x="50" y="48" textAnchor="middle" className="fill-foreground text-[24px] font-bold">
          {animated}%
        </text>
      </svg>
      <span className="text-xs text-muted-foreground">{label}</span>
    </div>
  );
};

export default ScoreGauge;
