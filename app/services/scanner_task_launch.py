from __future__ import annotations

import copy
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import requests
from fastapi import BackgroundTasks, HTTPException

from .. import db
from ..api.schemas import DeleteScannerTaskRequest, ScannerTaskRequest, StartScannerTaskRequest
from ..mpvm.common import as_dict, http_error
from ..mpvm.docker_vulnerabilities import docker_scan_group_name
from ..mpvm.scanner_task_rows import build_precheck_task_name, remote_scanner_task_exists
from ..mpvm_client import (
    MpVmApiError,
    build_asset_id_pdql_for_ips,
    build_scanner_task_payload,
    extract_asset_ids_from_csv,
    extract_ips_from_csv,
)
from ..services.scan_postprocess import SCAN_LOG, scan_log
from .main_host import host

if TYPE_CHECKING:
    from ..mpvm_client import MpVmClient


def _start_scanner_task_request(
    task_id: str, options: StartScannerTaskRequest, clean_idempotency_key: str | None,
    *, background_tasks: BackgroundTasks | None = None,
) -> dict[str, Any]:
    replay = db.get_operation_by_idempotency_key(clean_idempotency_key)
    if replay and replay.get("kind") == "scan_postprocess":
        workflow = host.CONTAINER.repositories.vm_workflows.by_operation(replay["operation_id"])
        return {
            "status": "started",
            "postprocess_run_id": replay["source_id"],
            "postprocess": db.get_scan_postprocess_run(replay["source_id"], include_items=True),
            "operation": replay,
            "operation_id": replay["operation_id"],
            "workflow_id": workflow.get("workflow_id") if workflow else None,
            "idempotent_replay": True,
        }
    client, token = host.require_mpvm()
    postprocess_run_id = str(uuid.uuid4())
    run_options = options.model_dump()
    if host.DOCKER_DYNAMIC_GROUP_ITERATIONS > 0:
        run_options["docker_dynamic_group"] = {
            "name": docker_scan_group_name(postprocess_run_id),
            "state": "planned",
        }
    postprocess_holder: dict[str, dict[str, Any]] = {}
    configuration_update: dict[str, Any] | None = None

    def ensure_postprocess_run(started_from: str) -> dict[str, Any]:
        if "run" not in postprocess_holder:
            postprocess_holder["run"] = db.create_scan_postprocess_run(
                postprocess_run_id,
                mp_task_id=task_id,
                started_from=started_from,
                options=run_options,
                idempotency_key=clean_idempotency_key,
            )
        return postprocess_holder["run"]

    try:
        configuration_update = host.sync_scanner_task_configuration_before_start(
            client=client,
            token=token,
            task_id=task_id,
        )
        result = host.start_scanner_task_impl(
            client=client,
            token=token,
            task_id=task_id,
            options=options,
            docker_group_run_id=postprocess_run_id,
            before_remote_start=ensure_postprocess_run,
        )
    except Exception as exc:
        if "run" in postprocess_holder:
            try:
                host.finish_provisional_scan_start_failure(
                    run_id=postprocess_run_id,
                    auth=client.auth,
                    token=token,
                    error=exc,
                )
            except Exception:
                SCAN_LOG.exception(
                    "[scan-postprocess] failed to finalize provisional scanner start "
                    "postprocess_run_id=%s task_id=%s",
                    postprocess_run_id,
                    task_id,
                )
        if isinstance(exc, MpVmApiError | requests.RequestException):
            raise http_error(exc) from exc
        raise

    result["configuration_update"] = configuration_update
    if result.get("status") != "started":
        return result
    created_before_start = "run" in postprocess_holder
    docker_group = result.get("docker_dynamic_group")
    if not created_before_start and isinstance(docker_group, dict):
        run_options["docker_dynamic_group"] = docker_group
    postprocess = ensure_postprocess_run(str(result["started_from"]))
    if created_before_start:
        postprocess = db.get_scan_postprocess_run(postprocess_run_id) or postprocess
    if background_tasks is None:
        host.schedule_scan_postprocess(postprocess_run_id, client.auth, token)
    else:
        background_tasks.add_task(host.schedule_scan_postprocess, postprocess_run_id, client.auth, token)
    return {
        **result,
        "postprocess_run_id": postprocess_run_id,
        "postprocess": postprocess,
        "operation_id": postprocess_run_id,
    }


def sync_scanner_task_configuration_before_start(
    *,
    client: MpVmClient,
    token: str,
    task_id: str,
) -> dict[str, Any]:
    """Make the locally saved task configuration authoritative before validation and start."""
    local_task = db.get_scan_task(task_id)
    task_payload = local_task.get("payload") if isinstance(local_task, dict) else None
    if not isinstance(task_payload, dict) or not task_payload:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "LOCAL_SCANNER_TASK_CONFIGURATION_REQUIRED",
                "message": "Save the scanner task in the client before starting it.",
            },
        )

    payload = copy.deepcopy(task_payload)
    update_response = client.update_scanner_task(token, task_id, payload)
    db.record_scan_task(
        mp_task_id=task_id,
        payload=payload,
        status="updated_before_start",
        remote_response=update_response,
    )
    scan_log(
        logging.INFO,
        "scanner_task_configuration_synced_before_start",
        task_id=task_id,
    )
    return {
        "status": "updated",
        "response": update_response,
    }


def delete_scanner_task_idempotent(
    task_id: str,
    payload: DeleteScannerTaskRequest,
    idempotency_key: str | None,
) -> dict[str, Any]:
    clean_key = idempotency_key if isinstance(idempotency_key, str) else None
    replay = db.get_operation_by_idempotency_key(clean_key)
    if replay:
        if replay.get("kind") != "task_delete":
            raise HTTPException(status_code=409, detail={"code": "IDEMPOTENCY_KEY_CONFLICT", "message": "Idempotency key belongs to another operation.", "component": "operations"})
        return {**(replay.get("result") or {}), "idempotent_replay": True, "operation_id": replay["operation_id"]}
    operation_id = str(uuid.uuid4())
    if payload.mode == "auto":
        initial_stage = "checking_remote_task"
        initial_message = "Checking scanner task in MP VM before deletion."
    elif payload.mode == "local_only":
        initial_stage = "deleting_local_task"
        initial_message = "Deleting scanner task from local database."
    else:
        initial_stage = "deleting_remote_task"
        initial_message = "Deleting scanner task from MP VM."
    db.register_operation(
        operation_id,
        kind="task_delete",
        source_id=operation_id,
        status="running",
        stage=initial_stage,
        progress_percent=10,
        subject_type="scanner_task",
        subject_id=task_id,
        subject_label=task_id,
        message=initial_message,
        request={"mode": payload.mode},
        idempotency_key=clean_key,
    )
    try:
        result = delete_scanner_task_impl(task_id, payload)
    except Exception as exc:
        db.register_operation(
            operation_id,
            kind="task_delete",
            source_id=operation_id,
            status="failed",
            stage="failed",
            progress_percent=100,
            subject_type="scanner_task",
            subject_id=task_id,
            subject_label=task_id,
            message="Scanner task deletion failed.",
            error={"message": str(exc)[:1000]},
            idempotency_key=clean_key,
            finished_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        raise
    db.register_operation(
        operation_id,
        kind="task_delete",
        source_id=operation_id,
        status="completed",
        stage="completed",
        progress_percent=100,
        subject_type="scanner_task",
        subject_id=task_id,
        subject_label=task_id,
        message=(
            "Scanner task deleted from local database."
            if result.get("localOnly")
            else "Scanner task deleted from MP VM."
        ),
        request={"mode": payload.mode},
        result=result,
        idempotency_key=clean_key,
        finished_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )
    return {**result, "operation_id": operation_id}


def scanner_task_payload(payload: ScannerTaskRequest) -> dict[str, Any]:
    if payload.raw_payload:
        raw = payload.raw_payload
        include = as_dict(raw.get("include"))
        exclude = as_dict(raw.get("exclude"))
        agents = as_dict(raw.get("agents"))
        discovery = as_dict(raw.get("hostDiscovery"))
        overrides = as_dict(raw.get("overrides"))
        transports = as_dict(overrides.get("transports"))
        validated = ScannerTaskRequest.model_validate({
            "name": raw.get("name") or payload.name,
            "description": raw.get("description") or payload.description,
            "scope_id": raw.get("scope") or payload.scope_id,
            "profile_id": raw.get("profile") or payload.profile_id,
            "include_targets": include.get("targets") or payload.include_targets,
            "exclude_targets": exclude.get("targets") or payload.exclude_targets,
            "agent_ids": agents.get("agentIds") or payload.agent_ids,
            "credential_id": db._credential_id_from_payload(raw) or payload.credential_id,
            "credential_transport": "ssh" if isinstance(transports.get("terminal"), dict) else payload.credential_transport,
            "host_discovery_enabled": discovery.get("enabled", payload.host_discovery_enabled),
            "host_discovery_profile_id": discovery.get("profile") or payload.host_discovery_profile_id,
            "time_zone": ((raw.get("triggerParameters") or {}).get("timeZone") or payload.time_zone)
            if isinstance(raw.get("triggerParameters"), dict) else payload.time_zone,
            "is_fqdn_priority": raw.get("isFqdnPriority", payload.is_fqdn_priority),
            "trigger_parameters": raw.get("triggerParameters"),
            "denied_scan_settings": raw.get("deniedScanSettings"),
        })
        return host.scanner_task_payload(validated)
    include_targets = [item.strip() for item in payload.include_targets if item.strip()]
    if not include_targets:
        raise HTTPException(status_code=422, detail="include_targets is required")
    return build_scanner_task_payload(
        name=payload.name,
        description=payload.description,
        scope_id=payload.scope_id,
        profile_id=payload.profile_id,
        include_targets=include_targets,
        exclude_targets=[item.strip() for item in payload.exclude_targets if item.strip()],
        agent_ids=[item.strip() for item in payload.agent_ids if item.strip()],
        credential_id=payload.credential_id,
        credential_transport=payload.credential_transport,
        host_discovery_enabled=payload.host_discovery_enabled or bool(payload.host_discovery_profile_id),
        host_discovery_profile_id=payload.host_discovery_profile_id,
        time_zone=payload.time_zone,
        is_fqdn_priority=payload.is_fqdn_priority,
        trigger_parameters=(payload.trigger_parameters.model_dump(exclude_none=True)
                            if payload.trigger_parameters else None),
        denied_scan_settings=(payload.denied_scan_settings.model_dump(exclude_none=True)
                              if payload.denied_scan_settings else None),
    )


def start_scanner_task_impl(
    *,
    client: MpVmClient,
    token: str,
    task_id: str,
    options: StartScannerTaskRequest,
    docker_group_run_id: str | None = None,
    before_remote_start: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": task_id,
        "precheck": None,
        "start": None,
        "finish": None,
    }
    if not options.skip_validation:
        valid, error = client.validate_scanner_task_with_retry(
            token,
            task_id,
            timeout_seconds=options.create_settle_seconds,
            poll_seconds=min(options.task_poll_seconds, 5),
        )
        if not valid:
            db.update_scan_task_status(task_id, "validation_failed", {"error": error})
            return {**result, "status": "validation_failed", "error": error}

    if options.precheck_enabled:
        precheck_result = run_precheck_for_scanner_task(client=client, token=token, task_id=task_id, options=options)
        result["precheck"] = precheck_result
        successful_targets = precheck_result.get("successful_targets") or []
        if not successful_targets:
            db.update_scan_task_status(task_id, "precheck_failed", precheck_result)
            return {**result, "status": "precheck_failed"}

    started_from = datetime.now(UTC).isoformat()
    if before_remote_start:
        before_remote_start(started_from)
    docker_group = (
        host.prepare_docker_dynamic_group_for_scan(
            client=client,
            token=token,
            run_id=docker_group_run_id,
            task_id=task_id,
            persist_lifecycle=before_remote_start is not None,
        )
        if docker_group_run_id
        else None
    )
    try:
        if before_remote_start and docker_group_run_id and docker_group:
            db.update_scan_postprocess_docker_group(
                docker_group_run_id,
                state="starting",
                scanner_start_requested_at=db.now_utc(),
            )
        start_response = client.start_scanner_task_with_retry(
            token,
            task_id,
            timeout_seconds=options.create_settle_seconds,
            poll_seconds=min(options.task_poll_seconds, 5),
        )
    except Exception as exc:
        if docker_group and before_remote_start and docker_group_run_id:
            try:
                db.update_scan_postprocess_docker_group(
                    docker_group_run_id,
                    state="start_failed",
                    scanner_start_error=str(exc)[:4000],
                )
            except Exception:
                SCAN_LOG.exception(
                    "[scan-postprocess] failed to persist scanner start failure for Docker group "
                    "postprocess_run_id=%s task_id=%s",
                    docker_group_run_id,
                    task_id,
                )
        elif docker_group:
            scan_log(
                logging.WARNING,
                "docker_dynamic_group_cleanup_skipped_without_lifecycle_record",
                task_id=task_id,
                group_id=docker_group.get("id"),
                group_name=docker_group.get("name"),
            )
        raise
    result["start"] = start_response
    result["docker_dynamic_group"] = docker_group
    if before_remote_start and docker_group_run_id and docker_group:
        try:
            db.update_scan_postprocess_docker_group(
                docker_group_run_id,
                state="active",
                scanner_started_at=started_from,
            )
        except Exception:
            SCAN_LOG.exception(
                "[scan-postprocess] scanner started but Docker group lifecycle update failed "
                "postprocess_run_id=%s task_id=%s",
                docker_group_run_id,
                task_id,
            )
    try:
        db.update_scan_task_status(task_id, "started", start_response)
    except Exception:
        SCAN_LOG.exception(
            "[scan-postprocess] scanner started but local task status update failed task_id=%s",
            task_id,
        )
    return {**result, "status": "started", "started_from": started_from}


def run_precheck_for_scanner_task(
    *,
    client: MpVmClient,
    token: str,
    task_id: str,
    options: StartScannerTaskRequest,
) -> dict[str, Any]:
    local_task = db.get_scan_task(task_id)
    if not local_task or not isinstance(local_task.get("payload"), dict):
        raise HTTPException(status_code=404, detail="Local scanner task payload not found. Create or update the task first.")

    audit_payload = copy.deepcopy(local_task["payload"])
    precheck_payload = copy.deepcopy(audit_payload)
    precheck_payload["name"] = build_precheck_task_name(options.precheck_task_prefix, str(audit_payload.get("name") or task_id))
    if options.precheck_profile_id:
        precheck_payload["profile"] = options.precheck_profile_id

    precheck_task_id = client.create_scanner_task(token, precheck_payload)
    db.record_scan_task(
        mp_task_id=precheck_task_id,
        payload=precheck_payload,
        status="precheck_created",
        remote_response={"audit_task_id": task_id},
    )

    if not options.skip_validation:
        valid, error = client.validate_scanner_task_with_retry(
            token,
            precheck_task_id,
            timeout_seconds=options.create_settle_seconds,
            poll_seconds=min(options.precheck_poll_seconds, 5),
        )
        if not valid:
            requested_targets = precheck_payload.get("include", {}).get("targets", []) if isinstance(precheck_payload.get("include"), dict) else []
            response = {
                "id": precheck_task_id, "task_id": precheck_task_id, "audit_task_id": task_id,
                "valid": False, "error": error, "successful_targets": [],
                "successful_target_count": 0, "false_targets": requested_targets,
                "false_target_count": len(requested_targets), "requested_target_count": len(requested_targets),
            }
            db.update_scan_task_status(precheck_task_id, "precheck_validation_failed", response)
            return {**response, "message": error}

    started_from = datetime.now(UTC).isoformat()
    start_response = client.start_connection_check_with_retry(
        token,
        precheck_task_id,
        timeout_seconds=options.create_settle_seconds,
        poll_seconds=min(options.precheck_poll_seconds, 5),
    )
    db.update_scan_task_status(precheck_task_id, "precheck_started", start_response)

    targets, message = client.wait_for_connection_check_targets(
        token,
        precheck_task_id,
        time_from=started_from,
        timeout_seconds=options.precheck_timeout_minutes * 60,
        stop_after_seconds=options.precheck_max_runtime_minutes * 60,
        poll_seconds=options.precheck_poll_seconds,
        jobs_limit=options.precheck_jobs_limit,
    )
    requested_targets = audit_payload.get("include", {}).get("targets", []) if isinstance(audit_payload.get("include"), dict) else []
    requested_targets = [str(value).strip() for value in requested_targets if str(value).strip()]
    successful_set = set(targets)
    false_targets = [value for value in requested_targets if value not in successful_set]
    status = "precheck_finished" if targets else "precheck_failed"
    precheck_result = {
        "task_id": precheck_task_id,
        "audit_task_id": task_id,
        "successful_targets": targets,
        "successful_target_count": len(targets),
        "false_targets": false_targets,
        "false_target_count": len(false_targets),
        "requested_target_count": len(requested_targets),
        "message": message,
    }
    db.update_scan_task_status(precheck_task_id, status, precheck_result)

    if targets:
        include = as_dict(audit_payload.get("include"))
        include["targets"] = targets
        if include.get("assetsGroups"):
            # Group-based tasks are narrowed to the reachable members found by the precheck.
            include["assetsGroups"] = []
        audit_payload["include"] = include
        update_response = client.update_scanner_task(token, task_id, audit_payload)
        db.record_scan_task(
            mp_task_id=task_id,
            payload=audit_payload,
            status="precheck_updated_targets",
            remote_response={"precheck": precheck_result, "update": update_response},
        )

    return precheck_result


def run_false_targets_precheck(
    *, client: MpVmClient, token: str, source_precheck_task_id: str,
    options: StartScannerTaskRequest,
) -> dict[str, Any]:
    source = db.get_scan_task(source_precheck_task_id)
    result = source.get("last_remote_response") if source else None
    if not source or not isinstance(result, dict):
        raise HTTPException(status_code=404, detail="Precheck run not found.")
    false_targets = result.get("false_targets")
    audit_task_id = result.get("audit_task_id")
    if not isinstance(false_targets, list) or not false_targets:
        raise HTTPException(status_code=422, detail="This precheck run has no false targets.")
    if not audit_task_id:
        raise HTTPException(status_code=422, detail="The source audit task is unavailable for this precheck run.")

    retry_payload = copy.deepcopy(source.get("payload") or {})
    include = as_dict(retry_payload.get("include"))
    include["targets"] = [str(value).strip() for value in false_targets if str(value).strip()]
    retry_payload["include"] = include
    retry_payload["name"] = build_precheck_task_name("MP VM false retry", str(retry_payload.get("name") or audit_task_id))
    retry_task_id = client.create_scanner_task(token, retry_payload)
    lineage = {"audit_task_id": audit_task_id, "parent_precheck_task_id": source_precheck_task_id}
    db.record_scan_task(mp_task_id=retry_task_id, payload=retry_payload, status="precheck_created", remote_response=lineage)

    if not options.skip_validation:
        valid, error = client.validate_scanner_task_with_retry(
            token, retry_task_id, timeout_seconds=options.create_settle_seconds,
            poll_seconds=min(options.precheck_poll_seconds, 5),
        )
        if not valid:
            failed = {
                **lineage, "task_id": retry_task_id, "valid": False, "error": error,
                "successful_targets": [], "successful_target_count": 0,
                "false_targets": include["targets"], "false_target_count": len(include["targets"]),
                "requested_target_count": len(include["targets"]),
            }
            db.update_scan_task_status(retry_task_id, "precheck_validation_failed", failed)
            return {**failed, "message": error}

    started_from = datetime.now(UTC).isoformat()
    started = client.start_connection_check_with_retry(
        token, retry_task_id, timeout_seconds=options.create_settle_seconds,
        poll_seconds=min(options.precheck_poll_seconds, 5),
    )
    db.update_scan_task_status(retry_task_id, "precheck_started", {**lineage, "start": started})
    successful_targets, message = client.wait_for_connection_check_targets(
        token, retry_task_id, time_from=started_from,
        timeout_seconds=options.precheck_timeout_minutes * 60,
        stop_after_seconds=options.precheck_max_runtime_minutes * 60,
        poll_seconds=options.precheck_poll_seconds, jobs_limit=options.precheck_jobs_limit,
    )
    successful_set = set(successful_targets)
    remaining_false = [value for value in include["targets"] if value not in successful_set]
    retry_result = {
        **lineage, "task_id": retry_task_id, "successful_targets": successful_targets,
        "successful_target_count": len(successful_targets), "false_targets": remaining_false,
        "false_target_count": len(remaining_false), "requested_target_count": len(include["targets"]),
        "message": message,
    }
    db.update_scan_task_status(retry_task_id, "precheck_finished" if successful_targets else "precheck_failed", retry_result)
    return retry_result


def delete_scanner_task_impl(task_id: str, payload: DeleteScannerTaskRequest) -> dict[str, Any]:
    if payload.mode == "local_only":
        db.delete_scan_task(task_id)
        host.CONTAINER.services.scanner_task_folders.unassign_task(task_id)
        return {"id": task_id, "mode": payload.mode, "localOnly": True}

    client, token = host.require_mpvm()
    try:
        if payload.mode == "auto":
            if not remote_scanner_task_exists(client, token, task_id):
                db.delete_scan_task(task_id)
                host.CONTAINER.services.scanner_task_folders.unassign_task(task_id)
                return {"id": task_id, "mode": payload.mode, "localOnly": True, "remoteFound": False}
            response = client.delete_scanner_task(token, task_id, mode="delete_v3")
            db.delete_scan_task(task_id)
            host.CONTAINER.services.scanner_task_folders.unassign_task(task_id)
            return {**response, "mode": payload.mode, "remoteFound": True}

        response = client.delete_scanner_task(
            token,
            task_id,
            mode=payload.mode,
            put_payload=payload.put_payload,
        )
        db.delete_scan_task(task_id)
        host.CONTAINER.services.scanner_task_folders.unassign_task(task_id)
        return response
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


def remove_assets_after_export(
    *,
    client: MpVmClient,
    token: str,
    csv_text: str,
    import_run_id: int | None,
    utc_offset: str | None,
    group_ids: list[str],
    include_nested_groups: bool,
    asset_ids: list[str],
    timeout_minutes: float,
    poll_seconds: float,
) -> dict[str, Any]:
    resolved_asset_ids = extract_asset_ids_from_csv(csv_text)
    resolution_source = "export_csv"
    if not resolved_asset_ids:
        resolved_asset_ids = list(asset_ids)
        resolution_source = "request_asset_ids"
    if not resolved_asset_ids:
        ips = extract_ips_from_csv(csv_text)
        resolved_asset_ids = resolve_asset_ids_by_ips(
            client=client,
            token=token,
            ips=ips,
            utc_offset=utc_offset,
            group_ids=group_ids,
            include_nested_groups=include_nested_groups,
        )
        resolution_source = "ip_resolution_pdql"

    if not resolved_asset_ids:
        db.record_asset_removal(
            import_run_id=import_run_id,
            operation_id=None,
            asset_ids=[],
            status="skipped",
            message="No asset IDs found in CSV or via IP resolution.",
        )
        return {"status": "skipped", "message": "No asset IDs found.", "asset_count": 0}

    operation_id = client.remove_assets(token, resolved_asset_ids)
    ok, message, raw_response = client.wait_for_asset_removal(
        token,
        operation_id,
        timeout_seconds=timeout_minutes * 60,
        poll_seconds=poll_seconds,
    )
    status = "completed" if ok else "failed"
    db.record_asset_removal(
        import_run_id=import_run_id,
        operation_id=operation_id,
        asset_ids=resolved_asset_ids,
        status=status,
        message=message,
        raw_response=raw_response,
    )
    return {
        "status": status,
        "operation_id": operation_id,
        "asset_count": len(resolved_asset_ids),
        "resolution_source": resolution_source,
        "message": message,
    }


def resolve_asset_ids_by_ips(
    *,
    client: MpVmClient,
    token: str,
    ips: list[str],
    utc_offset: str | None,
    group_ids: list[str],
    include_nested_groups: bool,
) -> list[str]:
    ids: list[str] = []
    for chunk in chunks(ips, 100):
        pdql = build_asset_id_pdql_for_ips(chunk)
        pdql_token = client.create_pdql_token(
            token,
            pdql,
            utc_offset=utc_offset,
            selected_group_ids=group_ids,
            include_nested_groups=include_nested_groups,
            asset_ids=[],
        )
        ids.extend(extract_asset_ids_from_csv(client.fetch_csv(token, pdql_token)))
    seen: set[str] = set()
    result: list[str] = []
    for item in ids:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[index : index + size] for index in range(0, len(items), size)]
