"""Unit tests for Docker-backed namespace lifecycle management."""

from unittest.mock import MagicMock, patch

from redroom.infrastructure.namespace_lifecycle import NamespaceLifecycle


def _docker_result(stdout: bytes = b"ok\n", returncode: int = 0) -> MagicMock:
    result = MagicMock()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = b""
    return result


@patch("redroom.infrastructure.namespace_lifecycle.subprocess.run")
def test_namespace_lifecycle_initialization(mock_run):
    """Test namespace lifecycle manager initializes with Docker."""
    mock_run.return_value = _docker_result(b"Docker version 24.0.0\n")

    manager = NamespaceLifecycle()

    assert manager.backend == "docker"
    mock_run.assert_called()


@patch("redroom.infrastructure.namespace_lifecycle.time.sleep", return_value=None)
@patch("redroom.infrastructure.namespace_lifecycle.subprocess.run")
def test_create_shadow_namespace(mock_run, _sleep):
    """Test shadow container creation via docker run."""
    mock_run.return_value = _docker_result(b"abc123def456\n")

    manager = NamespaceLifecycle()
    namespace = manager.create_shadow_namespace("demo-fintech")

    assert namespace.startswith("shadow-demo-fintech-")
    docker_run_calls = [
        call for call in mock_run.call_args_list
        if call.args and call.args[0][:2] == ["docker", "run"]
    ]
    assert docker_run_calls
    run_cmd = docker_run_calls[0].args[0]
    assert "--memory" in run_cmd
    assert "512m" in run_cmd
    assert "--cpus" in run_cmd


@patch("redroom.infrastructure.namespace_lifecycle.subprocess.run")
def test_cleanup_namespace(mock_run):
    """Test shadow container stop and remove."""
    mock_run.return_value = _docker_result()

    manager = NamespaceLifecycle()
    manager.cleanup_namespace("shadow-test123")

    commands = [call.args[0] for call in mock_run.call_args_list if call.args]
    assert ["docker", "stop", "shadow-test123"] in commands
    assert ["docker", "rm", "shadow-test123"] in commands


@patch("redroom.infrastructure.namespace_lifecycle.subprocess.run")
def test_get_namespace_info(mock_run):
    """Test getting Docker container information."""
    inspect_json = b'''[{
        "Id": "0123456789abcdef",
        "Created": "2026-01-01T00:00:00Z",
        "State": {"Status": "running", "Running": true}
    }]'''

    def _side_effect(cmd, *args, **kwargs):
        if cmd[:2] == ["docker", "--version"]:
            return _docker_result(b"Docker version 24.0.0\n")
        return _docker_result(inspect_json)

    mock_run.side_effect = _side_effect

    manager = NamespaceLifecycle()
    info = manager.get_namespace_info("shadow-test123")

    assert info is not None
    assert info["namespace"] == "shadow-test123"
    assert info["backend"] == "docker"
    assert info["status"] == "running"
    assert info["running"] is True
    assert info["container_id"] == "0123456789ab"
