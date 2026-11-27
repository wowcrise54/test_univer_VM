"""Resume the Wazuh ZIP transfer without appending an unverified response."""

import json
import re
from collections.abc import Callable
from pathlib import Path
from threading import Event

import requests

CONTENT_RANGE = re.compile(r"bytes (\d+)-(\d+)/(\d+)")
DOWNLOAD_ATTEMPTS = 4


class SnapshotUnavailable(Exception):
    pass


class SnapshotCancelled(Exception):
    pass


def _read_cache_metadata(path: Path) -> dict:
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return {}
    return metadata if isinstance(metadata, dict) else {}


def _validator(response: requests.Response) -> str:
    etag = response.headers.get("ETag", "")
    return etag if etag.startswith('"') else response.headers.get("Last-Modified", "")


def download_snapshot(
    session: requests.Session, url: str, cache: Path, cancel: Event,
    report: Callable[[int, int], None],
) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / "snapshot.zip.part"
    sidecar = cache / "snapshot.json"
    state = _read_cache_metadata(sidecar)

    for attempt in range(DOWNLOAD_ATTEMPTS):
        if cancel.is_set():
            raise SnapshotCancelled
        size = state.get("size")
        offset = archive.stat().st_size if archive.exists() and state.get("url") == url else 0
        if not isinstance(size, int) or offset > size:
            offset = 0
        if offset and offset == size:
            report(offset, size)
            return archive
        if not state.get("validator"):
            offset = 0
        headers = {"Accept-Encoding": "identity"}
        if offset:
            headers.update(Range=f"bytes={offset}-", **{"If-Range": state["validator"]})
        try:
            with session.get(url, headers=headers, timeout=(5, 30), stream=True, allow_redirects=False) as response:
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise SnapshotUnavailable("Сервер вернул ZIP с неожиданным кодированием.")
                validator = _validator(response)
                if response.status_code == 206 and offset:
                    part = CONTENT_RANGE.fullmatch(response.headers.get("Content-Range", ""))
                    if (part is None or int(part[1]) != offset or int(part[2]) != size - 1
                            or int(part[3]) != size or (validator and validator != state["validator"])):
                        raise SnapshotUnavailable("Сервер вернул неверный диапазон ZIP.")
                elif response.status_code == 200:
                    if offset and (not validator or validator == state["validator"]):
                        raise SnapshotUnavailable("Сервер проигнорировал Range и вернул весь ZIP.")
                    content_length = response.headers.get("Content-Length", "")
                    if not content_length.isdecimal() or int(content_length) <= 0:
                        raise SnapshotUnavailable("Сервер не указал размер ZIP.")
                    offset, size = 0, int(content_length)
                    state = {"url": url, "size": size, "validator": validator}
                else:
                    response.raise_for_status()
                    raise SnapshotUnavailable("Сервер вернул неожиданный ответ при загрузке ZIP.")

                assert isinstance(size, int)
                with archive.open("ab" if offset else "wb") as output:
                    if not offset:
                        temporary = sidecar.with_suffix(".tmp")
                        temporary.write_text(json.dumps(state), encoding="utf-8")
                        temporary.replace(sidecar)
                    report(offset, size)
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if cancel.is_set():
                            raise SnapshotCancelled
                        if offset + len(chunk) > size:
                            raise SnapshotUnavailable("Ответ превышает заявленный размер ZIP.")
                        output.write(chunk)
                        offset += len(chunk)
                        report(offset, size)
                if offset == size:
                    return archive
                raise requests.ConnectionError("Incomplete ZIP")
        except requests.RequestException as exc:
            status = exc.response.status_code if exc.response is not None else None
            if (status is not None and status not in {408, 500, 502, 503, 504}) or attempt + 1 == DOWNLOAD_ATTEMPTS:
                raise SnapshotUnavailable("Загрузка ZIP прервана. Полученная часть сохранена.") from exc
            if cancel.wait(2 ** attempt):
                raise SnapshotCancelled from exc
    raise AssertionError("Unreachable download state")
