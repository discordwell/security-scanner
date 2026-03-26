from __future__ import annotations

import argparse
import asyncio
import sys


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

    args = parser.parse_args()
    if args.command == "serve":
        cmd_serve(args)
    elif args.command == "create-key":
        cmd_create_key(args)
    elif args.command == "migrate":
        cmd_migrate(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
