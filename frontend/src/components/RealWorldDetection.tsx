"use client";
import { useEffect, useState } from "react";
import { TrendingUp, Users, Shield, Zap } from "lucide-react";
import GridBackground from "./GridBackground";

interface PhishingRecord {
  id: string;
  url: string;
  detectedAt: string;
  threatLevel: string;
}

interface Stats {
  scans24h: string;
  activeUsers: string;
  threatsBlocked: string;
  detectionAccuracy: string;
  avgResponseTime: string;
  countriesProtected: string;
}

const RealWorldDetection = () => {
  const [records, setRecords] = useState<PhishingRecord[]>([]);
  const [stats, setStats] = useState<Stats>({
    scans24h: "2.4M",
    activeUsers: "842K",
    threatsBlocked: "12.3K",
    detectionAccuracy: "99.2%",
    avgResponseTime: "0.8s",
    countriesProtected: "156",
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Replace this with your real API endpoint
    fetch("https://api.example.com/recent-phishing") 
      .then((res) => res.json())
      .then((data) => {
        setRecords(data);
        setLoading(false);
      })
      .catch(() => {
        // fallback mock data if API fails
        setRecords([
          { id: "1", url: "http://fake-login.com", detectedAt: "2026-03-17 12:00", threatLevel: "High" },
          { id: "2", url: "http://phish-example.net", detectedAt: "2026-03-16 18:30", threatLevel: "Medium" },
          { id: "3", url: "http://malicious-site.org", detectedAt: "2026-03-15 09:20", threatLevel: "High" },
          { id: "4", url: "http://spam-alert.io", detectedAt: "2026-03-17 08:45", threatLevel: "Medium" },
          { id: "5", url: "http://credential-steal.com", detectedAt: "2026-03-17 02:15", threatLevel: "Critical" },
          { id: "6", url: "http://fake-bank.net", detectedAt: "2026-03-16 22:30", threatLevel: "High" },
        ]);
        setLoading(false);
      });
  }, []);

  const statCards = [
    { icon: Zap, label: "Scans (24h)", value: stats.scans24h, color: "cyan" },
    { icon: Users, label: "Active Users", value: stats.activeUsers, color: "green" },
    { icon: Shield, label: "Threats Blocked", value: stats.threatsBlocked, color: "red" },
    { icon: TrendingUp, label: "Detection Accuracy", value: stats.detectionAccuracy, color: "yellow" },
    { icon: Zap, label: "Avg Response Time", value: stats.avgResponseTime, color: "blue" },
    { icon: Users, label: "Countries Protected", value: stats.countriesProtected, color: "purple" },
  ];

  const getColorClass = (color: string) => {
    const colors: { [key: string]: string } = {
      cyan: "text-cyan-400",
      green: "text-green-400",
      red: "text-red-400",
      yellow: "text-yellow-400",
      blue: "text-blue-400",
      purple: "text-purple-400",
    };
    return colors[color] || "text-cyan-400";
  };

  return (
    <section className="relative px-8 py-24 bg-[#0b0f1a] text-white overflow-hidden">
      <GridBackground />
      <div className="relative z-10">
      <h2 className="text-4xl font-bold text-center mb-16">
        Real-World Phishing Detection
      </h2>

      {/* Stats Grid */}
      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto mb-16">
        {statCards.map((stat, idx) => {
          const Icon = stat.icon;
          return (
            <div
              key={idx}
              className="relative group rounded-xl p-[1px] bg-gradient-to-r from-gray-600 to-gray-700 hover:from-cyan-500 hover:to-blue-500 transition-all duration-300"
            >
              <div className="bg-[#0b0f1a] rounded-xl p-6 border border-[#1f2937] group-hover:border-cyan-500/50 transition-all">
                <div className="flex items-center justify-between mb-3">
                  <p className="text-gray-400 text-sm font-medium">{stat.label}</p>
                  <Icon className={`w-5 h-5 ${getColorClass(stat.color)}`} />
                </div>
                <p className={`text-3xl font-bold ${getColorClass(stat.color)}`}>
                  {stat.value}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Live Detections */}
      <h3 className="text-2xl font-bold mb-8 text-center">Latest Detections</h3>

      {loading ? (
        <p className="text-center text-gray-400">Loading recent detections...</p>
      ) : (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
          {records.map((record) => (
            <div
              key={record.id}
              className="relative group rounded-xl p-[2px] bg-gradient-to-r from-red-500 via-transparent to-red-500 animate-border cursor-pointer hover:shadow-lg hover:shadow-red-500/50 transition-all"
            >
              <div className="bg-[#0b0f1a] rounded-xl p-6 text-left h-full border border-[#1f2937] shadow-lg">
                <div className="flex items-start justify-between mb-3">
                  <h3 className="font-semibold text-sm text-cyan-400 truncate flex-1">
                    {record.url}
                  </h3>
                  <span className={`text-xs px-2 py-1 rounded ml-2 whitespace-nowrap ${
                    record.threatLevel === "Critical" ? "bg-red-900 text-red-200" :
                    record.threatLevel === "High" ? "bg-red-800 text-red-100" : "bg-yellow-800 text-yellow-100"
                  }`}>
                    {record.threatLevel}
                  </span>
                </div>
                <p className="text-gray-500 text-xs mb-3">
                  {record.detectedAt}
                </p>
                <div className="pt-3 border-t border-[#1f2937]">
                  <p className="text-gray-400 text-xs">Status: 
                    <span className="ml-2 text-green-400 font-semibold">🔴 Blocked</span>
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      </div>
    </section>
  );
};

export default RealWorldDetection;