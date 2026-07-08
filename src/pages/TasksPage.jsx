import { TaskBuilderPanel, TaskListPanel } from "../features/tasks/index.jsx";

export function TasksPage({
  busy,
  defaults,
  lookups,
  refreshTasks,
  runBusy,
  selectedTask,
  selectedTaskId,
  setSelectedTaskId,
  showAlert,
  session,
  systemStatus,
  tasks,
}) {
  return (
    <>
      <TaskListPanel
        tasks={tasks}
        lookups={lookups}
        selectedTaskId={selectedTaskId}
        setSelectedTaskId={setSelectedTaskId}
        refreshTasks={refreshTasks}
        busy={busy}
        showAlert={showAlert}
      />
      <TaskBuilderPanel
        defaults={defaults}
        lookups={lookups}
        tasks={tasks}
        selectedTask={selectedTask}
        selectedTaskId={selectedTaskId}
        setSelectedTaskId={setSelectedTaskId}
        refreshTasks={refreshTasks}
        busy={busy}
        runBusy={runBusy}
        showAlert={showAlert}
        session={session}
        systemStatus={systemStatus}
      />
    </>
  );
}
