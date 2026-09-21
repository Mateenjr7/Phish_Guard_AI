import { ReactNode, useRef } from "react";
import { motion, useMotionValue, useTransform } from "framer-motion";

interface Props {
  icon: ReactNode;
  title: string;
  description: string;
}

const FeatureCard = ({ icon, title, description }: Props) => {
  const cardRef = useRef<HTMLDivElement>(null);

  // 3D tilt motion values
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const rotateX = useTransform(y, [-50, 50], [15, -15]);
  const rotateY = useTransform(x, [-50, 50], [-15, 15]);

  const handleMouseMove = (e: React.MouseEvent) => {
    const rect = cardRef.current?.getBoundingClientRect();
    if (!rect) return;
    const px = e.clientX - rect.left - rect.width / 2;
    const py = e.clientY - rect.top - rect.height / 2;
    x.set(px);
    y.set(py);
  };

  const handleMouseLeave = () => {
    x.set(0);
    y.set(0);
  };

  return (
    <motion.div
      ref={cardRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      style={{ rotateX, rotateY }}
      className="relative group rounded-xl p-[2px] bg-gradient-to-r from-red-500 via-transparent to-red-500 animate-border shadow-xl cursor-pointer perspective-500"
    >
      <motion.div className="bg-[#111827] rounded-xl p-6 text-center h-full shadow-lg border border-[#1f2937]">
        <div className="mx-auto mb-4 text-red-500">{icon}</div>
        <h3 className="text-xl font-semibold mb-2">{title}</h3>
        <p className="text-gray-400">{description}</p>
      </motion.div>

      {/* Inner glowing pulse */}
      <div className="absolute inset-0 rounded-xl opacity-0 group-hover:opacity-50 pointer-events-none bg-red-500 blur-2xl transition duration-500"></div>
    </motion.div>
  );
};

export default FeatureCard;