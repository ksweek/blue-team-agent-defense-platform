from __future__ import annotations

import logging

from app.core.config import settings
from app.core.logging import configure_logging
from app.services.bootstrap import init_database, validate_runtime_configuration
from app.services.task_worker import run_worker_forever


def main() -> None:
    configure_logging()
    logger = logging.getLogger("app.worker.entry")
    logger.info(
        "initializing standalone worker process | env=%s bootstrap_mode=%s db=%s",
        settings.app_env,
        settings.bootstrap_mode,
        settings.database_summary,
    )
    validate_runtime_configuration(role="worker")
    init_database()
    run_worker_forever()


if __name__ == "__main__":
    main()
