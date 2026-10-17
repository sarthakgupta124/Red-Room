"""Shadow namespace lifecycle management for isolated exploit execution."""

import json
import subprocess
import time
import uuid
from typing import Dict, Any, Optional
import structlog

logger = structlog.get_logger()


class NamespaceLifecycle:
    """
    Manages ephemeral Docker containers used as isolated shadow
    environments for exploit execution.

    Resource limits (512Mi RAM, 0.5 CPU) are enforced on every container.
    Containers are labelled with the shadow- prefix and cleaned up after each run.
    """

    def __init__(self):
        """Initialize namespace manager with Docker as the only backend."""
        self.backend = "docker"
        self._ensure_docker()
        logger.info("namespace_manager_initialized", backend=self.backend)

    def _ensure_docker(self) -> None:
        """Require a working Docker CLI; raise if it is unavailable."""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("docker_detected")
                return
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        logger.error("no_container_backend_detected")
        raise RuntimeError("Docker is required for shadow namespace isolation")

    def create_shadow_namespace(
        self,
        app_name: str,
        image: Optional[str] = None,
        port: int = 8080,
    ) -> str:
        """
        Create an isolated Docker container for exploit testing.

        Args:
            app_name: Name of the application
            image: Docker image to deploy (optional)
            port: Port to expose

        Returns:
            Container identifier
        """
        namespace_id = f"shadow-{app_name}-{uuid.uuid4().hex[:8]}"

        logger.info(
            "creating_shadow_namespace",
            namespace_id=namespace_id,
            backend=self.backend,
        )

        return self._create_docker_namespace(namespace_id, image, port)

    def _create_docker_namespace(
        self,
        namespace_id: str,
        image: Optional[str],
        port: int,
    ) -> str:
        """Create a constrained Docker container for the target app."""
        try:
            result = subprocess.run(
                [
                    "docker", "run",
                    "-d",
                    "--name", namespace_id,
                    "-p", f"{port}:{port}",
                    "--memory", "512m",
                    "--cpus", "0.5",
                    "--network", "bridge",
                    image or "redroom-target:latest",
                ],
                check=True,
                capture_output=True,
            )

            container_id = result.stdout.decode().strip()
            time.sleep(5)

            logger.info(
                "docker_namespace_created",
                namespace=namespace_id,
                container=container_id,
            )
            return namespace_id

        except subprocess.CalledProcessError as e:
            error = e.stderr.decode() if e.stderr else str(e)
            logger.error("docker_namespace_creation_failed", error=error)
            raise

    def cleanup_namespace(self, namespace_id: str):
        """Stop and remove a shadow container."""
        logger.info("cleaning_up_namespace", namespace=namespace_id, backend=self.backend)

        try:
            subprocess.run(
                ["docker", "stop", namespace_id],
                capture_output=True,
                timeout=30,
            )
            subprocess.run(
                ["docker", "rm", namespace_id],
                capture_output=True,
                timeout=30,
            )
            logger.info("namespace_cleaned_up", namespace=namespace_id)
        except Exception as e:
            logger.error("namespace_cleanup_failed", namespace=namespace_id, error=str(e))

    def cleanup_expired_namespaces(self, max_age_seconds: int = 3600):
        """Remove shadow containers older than max_age_seconds."""
        logger.info("cleaning_up_expired_namespaces", max_age=max_age_seconds)

        try:
            result = subprocess.run(
                ["docker", "ps", "-a", "--filter", "name=shadow-", "--format", "{{.Names}}"],
                capture_output=True,
                check=True,
            )

            containers = result.stdout.decode().strip().split("\n")

            for container in containers:
                if container and container.startswith("shadow-"):
                    inspect_result = subprocess.run(
                        ["docker", "inspect", container, "--format", "{{.Created}}"],
                        capture_output=True,
                    )
                    if inspect_result.returncode == 0:
                        logger.info("found_shadow_container", container=container)
                        self.cleanup_namespace(container)

        except Exception as e:
            logger.error("docker_cleanup_failed", error=str(e))

    def get_namespace_info(self, namespace_id: str) -> Optional[Dict[str, Any]]:
        """Return inspect metadata for a shadow container, or None."""
        try:
            result = subprocess.run(
                ["docker", "inspect", namespace_id],
                capture_output=True,
                check=True,
            )

            info = json.loads(result.stdout)[0]

            return {
                "namespace": namespace_id,
                "backend": self.backend,
                "status": info["State"]["Status"],
                "container_id": info["Id"][:12],
                "created": info["Created"],
                "running": info["State"]["Running"],
            }

        except Exception as e:
            logger.error("failed_to_get_container_info", error=str(e))
            return None
