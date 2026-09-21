"use client";

import { cn } from "@/lib/utils";
import { ButtonHTMLAttributes } from "react";

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
}

export function InteractiveHoverButton({ className, children, ...props }: Props) {
  return (
    <button
      className={cn(
        "relative inline-flex items-center justify-center overflow-hidden rounded-xl px-6 py-3 font-semibold text-white transition-all duration-300",
        "bg-gradient-to-r from-red-500 to-red-600",
        "hover:scale-105 active:scale-95",
        "before:absolute before:inset-0 before:opacity-0 before:transition before:duration-300",
        "before:bg-gradient-to-r before:from-white/20 before:to-transparent",
        "hover:before:opacity-100",
        className
      )}
      {...props}
    >
      <span className="relative z-10">{children}</span>
    </button>
  );
}