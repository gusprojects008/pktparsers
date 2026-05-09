import time
import json
import threading
from logging import getLogger
from core.bootstrap import init

config = {
    "module_dependencies": ["c", "b", "c"],
    "system_dependencies": ["d", "e"],
    "argparse": {}
}

result = init(config)
operations = result.operations

ENABLE_SYSTEM_TESTS = True
RUN_ALL = False
INTERACTIVE_MODE = True

logger = getLogger(__name__)

def run_test(name: str, func, *args, **kwargs):
    if not should_run_test(name):
        logger.info(f"[SKIPPED] {name}")
        return

    logger.info(f"\n[TEST START] {name}")
    try:
        result = func(*args, **kwargs)
        logger.info(f"[TEST OK] {name} {result}")
        return result
    except Exception as e:
        logger.error(f"[TEST FAIL] {name}: {e}", exc_info=True)
    finally:
        logger.info(f"[TEST END] {name}\n")

def run_blocking_test(name: str, func, timeout: float = 10, **kwargs):
    if not should_run_test(name):
        logger.info(f"[SKIPPED] {name}")
        return

    logger.info(f"\n[TEST START] {name}")

    stop_event = threading.Event()

    def target():
        try:
            func(timeout=timeout, stop_event=stop_event, **kwargs)
        except Exception as e:
            logger.error(f"[THREAD ERROR] {name}: {e}", exc_info=True)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()

    try:
        thread.join(timeout)

        if thread.is_alive():
            logger.warning(f"[TIMEOUT] {name} exceeded {timeout}s, stopping...")
            stop_event.set()
            thread.join(2)

    except KeyboardInterrupt:
        logger.warning(f"[INTERRUPTED] {name} (Ctrl+C)")
        stop_event.set()
        thread.join(2)

    logger.info(f"[TEST END] {name}\n")

def should_run_test(name: str) -> bool:
    global RUN_ALL

    if not INTERACTIVE_MODE or RUN_ALL:
        return True

    choice = input(f"Run test '{name}'? [y/n/a]: ").strip().lower()

    if choice == "a":
        RUN_ALL = True
        return True

    return choice in ("y", "yes")

def run_tests():
    run_test(
        "operation1 example",
        operations.operation1,
        test=True,
        input_fullpath=test_input,
    )

    if ENABLE_SYSTEM_TESTS:
        logger.warning("SYSTEM TESTS ENABLED — this will modify system/network state")

        run_test(
            "operation2  [ENABLED SYSTEM TESTS]",
            operations.operation2
        )

        run_blocking_test(
            "operation3 (live test)",
            operations.operation3
        )

    else:
        logger.info("System tests disabled")

def main():
    run_tests()

if __name__ == "__main__":
    main()
