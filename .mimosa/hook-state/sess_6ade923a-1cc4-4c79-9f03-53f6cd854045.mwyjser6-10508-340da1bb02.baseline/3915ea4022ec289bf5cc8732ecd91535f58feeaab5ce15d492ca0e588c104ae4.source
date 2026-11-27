import { Component } from "react";
import { recordFrontendEvent } from "../../diagnostics.js";

export class TaskWorkspaceBoundary extends Component {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error, info) {
    recordFrontendEvent(
      "ui.task_workspace.render_error",
      { task_id: this.props.taskId, message: error.message },
      {
        level: "error",
        stack: `${error.stack || ""}\n${info.componentStack || ""}`,
      },
    );
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <main className="task-workspace">
        <div className="task-inline-error" role="alert">
          <h2>Не удалось отобразить задачу</h2>
          {this.props.taskId ? (
            <p>
              Задача: <code>{this.props.taskId}</code>
            </p>
          ) : null}
          <p>
            Вернитесь к списку и выберите другую задачу. Ошибка записана в
            журнал диагностики.
          </p>
          <button
            type="button"
            onClick={() => {
              this.props.onReturn();
              this.setState({ failed: false });
            }}
          >
            К списку задач
          </button>
        </div>
      </main>
    );
  }
}
