"""Install the built wheel in a clean environment, with no checkout imports."""
from pathlib import Path
import os
import subprocess
import tempfile
import venv


def main():
    root = Path(__file__).resolve().parents[1]
    wheels = list((root / ".tmp" / "python-dist").glob("nomos_agent_sdk-*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Expected one wheel in .tmp/python-dist; build into a clean output directory")
    with tempfile.TemporaryDirectory(prefix="nomos-wheel-test-") as directory:
        env_path = Path(directory) / "venv"
        venv.create(env_path, with_pip=True)
        python = env_path / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        subprocess.run([str(python), "-m", "pip", "install", "--no-deps", str(wheels[0])],
                       cwd=directory, check=True)
        subprocess.run([str(python), "-I", "-c",
                        "import nomos_sdk, nomos_langgraph; "
                        "from importlib.metadata import metadata; "
                        "assert metadata('nomos-agent-sdk')['License-Expression'] == 'Apache-2.0'; "
                        "print('Isolated SDK imports OK:', nomos_sdk.__file__)"],
                       cwd=directory, check=True)


if __name__ == "__main__":
    main()
