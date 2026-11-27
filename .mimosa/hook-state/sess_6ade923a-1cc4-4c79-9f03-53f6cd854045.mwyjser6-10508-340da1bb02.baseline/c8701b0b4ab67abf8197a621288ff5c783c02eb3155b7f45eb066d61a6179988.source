import { createContext, useContext } from "react";
import { useAppData } from "./useAppData.js";

const AppDataContext = createContext(null);

export function AppDataProvider({ routeId, children }) {
  const value = useAppData(routeId);
  return (
    <AppDataContext.Provider value={value}>{children}</AppDataContext.Provider>
  );
}

export function useAppDataContext() {
  const value = useContext(AppDataContext);
  if (!value)
    throw new Error("useAppDataContext must be used inside AppDataProvider");
  return value;
}
