from __future__ import annotations

from app.repositories.scanner_task_folders import ScannerTaskFolderRepository


class ScannerTaskFolderService:
    def __init__(self, repository: ScannerTaskFolderRepository) -> None:
        self._repository = repository

    def list(self) -> dict:
        return {"rows": self._repository.list()}

    def create(self, name: str, *, actor: str | None) -> dict:
        return self._repository.create(self._clean_name(name), actor=actor)

    def rename(self, folder_id: str, name: str, *, actor: str | None) -> dict:
        folder = self._repository.rename(folder_id, self._clean_name(name), actor=actor)
        if not folder:
            raise LookupError("Task folder not found.")
        return folder

    def delete(self, folder_id: str, *, actor: str | None = None) -> None:
        if not self._repository.delete(folder_id):
            raise LookupError("Task folder not found.")

    def assign(self, task_ids: list[str], folder_id: str | None, *, actor: str | None) -> None:
        clean_ids = list(dict.fromkeys(value.strip() for value in task_ids if value.strip()))
        if folder_id is not None and not self._repository.folder_exists(folder_id):
            raise LookupError("Task folder not found.")
        self._repository.assign(clean_ids, folder_id, actor=actor)

    def unassign_task(self, task_id: str) -> None:
        self._repository.unassign_task(task_id)

    @staticmethod
    def _clean_name(name: str) -> str:
        cleaned = name.strip()
        if not cleaned:
            raise ValueError("Task folder name cannot be empty.")
        if len(cleaned) > 120:
            raise ValueError("Task folder name must be 120 characters or fewer.")
        return cleaned
