"use client";

import "./globals.css";
import { useState, useEffect } from "react";
import { Sidebar } from "@/components/Sidebar";
import { ConnectionProvider } from "@/lib/connection";
import { PromptItem } from "@/lib/types";

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [pendingPrompts, setPendingPrompts] = useState<PromptItem[]>([]);
  const [isWsConnected, setIsWsConnected] = useState(false);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimer: NodeJS.Timeout | null = null;
    let isCancelled = false;

    function connect() {
      if (isCancelled) return;
      const wsUrl = process.env.NEXT_PUBLIC_CUSTOS_WS || "ws://localhost:8000/ws/approvals";
      try {
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
          if (!isCancelled) setIsWsConnected(true);
        };

        socket.onclose = () => {
          if (isCancelled) return;
          setIsWsConnected(false);
          reconnectTimer = setTimeout(connect, 3000);
        };

        socket.onerror = () => {
          if (!isCancelled) setIsWsConnected(false);
        };

        socket.onmessage = (event) => {
          if (isCancelled) return;
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === "initial_state") {
              setPendingPrompts(msg.pending_prompts || []);
            } else if (msg.type === "prompt_requested") {
              setPendingPrompts((prev) => [msg.data, ...prev]);
            } else if (msg.type === "prompt_resolved" || msg.type === "prompt_timed_out") {
              setPendingPrompts((prev) => prev.filter((p) => p.request_id !== msg.request_id));
            }
          } catch (e) {
            console.error("WS error:", e);
          }
        };
      } catch {
        if (!isCancelled) {
          setIsWsConnected(false);
          reconnectTimer = setTimeout(connect, 3000);
        }
      }
    }

    connect();

    return () => {
      isCancelled = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (socket) {
        socket.onopen = null;
        socket.onclose = null;
        socket.onerror = null;
        socket.onmessage = null;
        socket.close();
        socket = null;
      }
    };
  }, []);

  return (
    <html lang="en" data-theme="dark" className="dark">
      <head>
        <title>Custos // Autonomous AI Agent Security Control Plane</title>
        <meta name="description" content="Production-grade AI agent permission gateway and guardrail control plane" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Outfit:wght@300;400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="bg-[#030304] text-[#f8fafc] flex min-h-[100dvh] antialiased selection:bg-yellow-400/20 selection:text-yellow-300">
        <div className="ambient-mesh" />
        <div className="relative z-10 flex w-full min-h-[100dvh]">
          <Sidebar pendingCount={pendingPrompts.length} isWsConnected={isWsConnected} />
          <ConnectionProvider isWsConnected={isWsConnected}>
            <main className="flex-1 flex flex-col min-w-0 h-screen overflow-y-auto">
              {children}
            </main>
          </ConnectionProvider>
        </div>
      </body>
    </html>
  );
}
