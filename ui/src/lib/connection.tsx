"use client";

import React, { createContext, useContext } from "react";

interface ConnectionContextType {
  isWsConnected: boolean;
}

export const ConnectionContext = createContext<ConnectionContextType>({
  isWsConnected: false,
});

export function ConnectionProvider({
  isWsConnected,
  children,
}: {
  isWsConnected: boolean;
  children: React.ReactNode;
}) {
  return (
    <ConnectionContext.Provider value={{ isWsConnected }}>
      {children}
    </ConnectionContext.Provider>
  );
}

export function useConnection() {
  return useContext(ConnectionContext);
}
