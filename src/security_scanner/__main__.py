from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


def cmd_serve(args):
    import uvicorn
    uvicorn.run("security_scanner.api:app", host=args.host, port=args.port, reload=args.reload)


def cmd_create_key(args):
    from .config import get_settings
    from .db import Base, make_engine, make_session_factory
    from .auth import create_api_key

    async def run():
        settings = get_settings()
        engine = make_engine(settings.database_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        session_factory = make_session_factory(engine)
        key_id, raw_key = await create_api_key(
            session_factory,
            name=args.name,
            scopes=args.scopes.split(","),
            rate_limit=args.rate_limit,
        )
        print(f"Key ID:  {key_id}")
        print(f"API Key: {raw_key}")
        print("Save this key -- it cannot be retrieved again.")
        await engine.dispose()

    asyncio.run(run())


def cmd_migrate(args):
    from alembic import command
    from alembic.config import Config
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")


def cmd_analyze(args):
    from .config import get_settings
    from .logging_config import setup_logging
    from .repo_scanner import RepoScanner
    from .service import AnalysisService

    async def run():
        setup_logging()
        settings = get_settings()
        if args.no_llm:
            settings.llm_enabled = False
        elif args.llm:
            settings.llm_enabled = True
        if args.llm_model:
            settings.llm_model = args.llm_model
        if args.llm_budget:
            settings.llm_budget_tokens = args.llm_budget
        scanner = RepoScanner(analysis_service=AnalysisService(), settings=settings)
        repo_path = Path(args.path).resolve()
        if not repo_path.is_dir():
            print(f"Error: {repo_path} is not a directory", file=sys.stderr)
            sys.exit(1)

        report = await scanner.scan(repo_path)

        if args.format == "summary":
            _print_summary(report)
        else:
            output = report.model_dump_json(indent=2)
            if args.output:
                Path(args.output).write_text(output)
                print(f"Report written to {args.output}", file=sys.stderr)
            else:
                print(output)

    asyncio.run(run())


def _print_summary(report):
    from collections import Counter
    print(f"Repository: {report.repo_path}")
    print(f"Verdict:    {report.aggregate_verdict.value.upper()}")
    print(f"Files:      {report.file_count}")
    print(f"Summary:    {report.risk_summary}")
    print()

    sev = Counter(o.severity.value for o in report.top_findings)
    for s in ["critical", "high", "medium", "low", "info"]:
        if sev.get(s):
            print(f"  {s.upper()}: {sev[s]}")

    if report.top_findings:
        print()
        print("Top findings:")
        for obs in report.top_findings[:15]:
            print(f"  [{obs.severity.value.upper():8s}] {obs.message[:120]}")


def main():
    parser = argparse.ArgumentParser(prog="security-scanner")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="Start the API server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")

    key = sub.add_parser("create-key", help="Create an API key")
    key.add_argument("--name", required=True, help="Key name")
    key.add_argument("--scopes", default="submit,read", help="Comma-separated scopes")
    key.add_argument("--rate-limit", type=int, default=60, help="Requests per minute")

    sub.add_parser("migrate", help="Run database migrations")

    analyze = sub.add_parser("analyze", help="Analyze a repository directory")
    analyze.add_argument("path", help="Path to the repository directory")
    analyze.add_argument("--output", "-o", help="Output JSON report to file")
    analyze.add_argument("--format", choices=["json", "summary"], default="summary", help="Output format")
    analyze.add_argument("--llm", action="store_true", default=None, help="Enable LLM deep analysis")
    analyze.add_argument("--no-llm", action="store_true", help="Disable LLM analysis")
    analyze.add_argument("--llm-model", default=None, help="LLM model (default: claude-sonnet-4-20250514)")
    analyze.add_argument("--llm-budget", type=int, default=None, help="LLM token budget")

    args = parser.parse_args()
    if args.command == "serve":
        cmd_serve(args)
    elif args.command == "create-key":
        cmd_create_key(args)
    elif args.command == "migrate":
        cmd_migrate(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
