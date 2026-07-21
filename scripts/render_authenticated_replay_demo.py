from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path

import imageio_ffmpeg


ROOT = Path(__file__).resolve().parents[1]
VIDEO = ROOT / "evidence" / "dev-week" / "authenticated-replay-demo.webm"
NARRATION = ROOT / "evidence" / "dev-week" / "authenticated-replay-demo-narration.txt"
OUTPUT_DIR = ROOT / "output" / "demo"
VOICE = OUTPUT_DIR / "authenticated-replay-demo-voice.aiff"
OUTPUT = OUTPUT_DIR / "bug-bunny-authenticated-replay-demo.mp4"


def main() -> int:
    if platform.system() != "Darwin":
        raise SystemExit("Demo narration rendering currently requires macOS and its built-in `say` command.")
    say = shutil.which("say")
    if not say:
        raise SystemExit("macOS `say` is unavailable.")
    for required in (VIDEO, NARRATION):
        if not required.is_file():
            raise SystemExit(f"Missing required demo source: {required}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [say, "-v", "Samantha", "-r", "195", "-f", str(NARRATION), "-o", str(VOICE)],
        check=True,
    )
    subprocess.run(
        [
            imageio_ffmpeg.get_ffmpeg_exe(),
            "-y",
            "-loglevel",
            "warning",
            "-i",
            str(VIDEO),
            "-i",
            str(VOICE),
            "-map",
            "0:v:0",
            "-map",
            "1:a:0",
            "-c:v",
            "libx264",
            "-preset",
            "medium",
            "-crf",
            "20",
            "-pix_fmt",
            "yuv420p",
            "-af",
            "apad=pad_dur=3",
            "-c:a",
            "aac",
            "-b:a",
            "128k",
            "-shortest",
            "-movflags",
            "+faststart",
            str(OUTPUT),
        ],
        check=True,
    )
    print(OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
