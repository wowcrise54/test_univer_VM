import { TaskWorkspace } from "../features/tasks/TaskWorkspace.jsx";
import { TaskWorkspaceBoundary } from "../features/tasks/TaskWorkspaceBoundary.jsx";

export function TasksPage(props) {
  return (
    <TaskWorkspaceBoundary
      taskId={props.selectedTaskId}
      onReturn={() => props.setSelectedTaskId(null)}
    >
      <TaskWorkspace {...props} />
    </TaskWorkspaceBoundary>
  );
}
