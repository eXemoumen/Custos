import { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle: string;
  icon?: LucideIcon;
  variant?: "amber" | "blue" | "cyan" | "purple" | "emerald";
}

export function MetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = "blue",
}: MetricCardProps) {
  const colorMap = {
    amber: { text: "text-amber-400", border: "hover:border-amber-500/50", glow: "hover:shadow-amber-500/10" },
    blue: { text: "text-blue-400", border: "hover:border-blue-500/50", glow: "hover:shadow-blue-500/10" },
    cyan: { text: "text-cyan-400", border: "hover:border-cyan-500/50", glow: "hover:shadow-cyan-500/10" },
    purple: { text: "text-purple-400", border: "hover:border-purple-500/50", glow: "hover:shadow-purple-500/10" },
    emerald: { text: "text-emerald-400", border: "hover:border-emerald-500/50", glow: "hover:shadow-emerald-500/10" },
  };

  const style = colorMap[variant] || colorMap.blue;

  return (
    <div
      className={`bg-slate-900 border border-slate-800 rounded-xl p-5 relative overflow-hidden transition-all duration-200 shadow-md ${style.border} ${style.glow}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          {title}
        </span>
        {Icon && <Icon className={`w-4 h-4 ${style.text} opacity-80`} />}
      </div>
      <div className={`text-3xl font-bold font-mono my-2 tracking-tight ${style.text}`}>
        {value}
      </div>
      <p className="text-xs text-slate-500 font-normal">{subtitle}</p>
    </div>
  );
}
