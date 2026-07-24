import { VulnerabilitiesDashboard } from "../features/vulnerabilities/index.jsx";

export function VulnerabilitiesPage({ currentUser, showAlert }) {
  return (
    <VulnerabilitiesDashboard currentUser={currentUser} showAlert={showAlert} />
  );
}
