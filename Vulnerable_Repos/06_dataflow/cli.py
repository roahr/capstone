import sys
import os
import json
import argparse

from pipeline import Pipeline


def cmd_run(args):
    if not os.path.isfile(args.config):
        print(f"Config file not found: {args.config}")
        return 1

    pipe = Pipeline(args.config)
    print(f"Running pipeline: {pipe.name}")
    result = pipe.run()
    print(f"Completed in {result.get('duration', '?')}s")
    print(f"Rows processed: {result.get('rows_inserted', 0)}")
    return 0


def cmd_status(args):
    if not os.path.isfile(args.config):
        print(f"Config file not found: {args.config}")
        return 1

    pipe = Pipeline(args.config)
    print(json.dumps(pipe.state, indent=2, default=str))
    return 0


def cmd_reset(args):
    if not os.path.isfile(args.config):
        print(f"Config file not found: {args.config}")
        return 1

    pipe = Pipeline(args.config)
    pipe.reset()
    print(f"Pipeline '{pipe.name}' state cleared.")
    return 0


def cmd_exec(args):
    command = " ".join(args.command)
    if not command:
        print("No command specified.")
        return 1

    print(f"Executing: {command}")
    return os.system(command)


def main():
    parser = argparse.ArgumentParser(description="DataFlow ETL Pipeline CLI")
    subparsers = parser.add_subparsers(dest="action")

    run_parser = subparsers.add_parser("run", help="Execute a pipeline")
    run_parser.add_argument("--config", "-c", required=True, help="Pipeline YAML config")

    status_parser = subparsers.add_parser("status", help="Show pipeline state")
    status_parser.add_argument("--config", "-c", required=True, help="Pipeline YAML config")

    reset_parser = subparsers.add_parser("reset", help="Clear checkpoint data")
    reset_parser.add_argument("--config", "-c", required=True, help="Pipeline YAML config")

    exec_parser = subparsers.add_parser("exec", help="Run a maintenance command")
    exec_parser.add_argument("command", nargs="+", help="Command to run")

    args = parser.parse_args()
    if args.action is None:
        parser.print_help()
        return 0

    handlers = {
        "run": cmd_run,
        "status": cmd_status,
        "reset": cmd_reset,
        "exec": cmd_exec,
    }

    return handlers[args.action](args)


if __name__ == "__main__":
    sys.exit(main() or 0)
