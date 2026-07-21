from __future__ import annotations

import asyncio
import os
import re
import subprocess
from pathlib import Path

import edge_tts
import imageio_ffmpeg


ROOT = Path(__file__).resolve().parents[1]
VIDEO = ROOT / "evidence" / "dev-week" / "controlx-authenticated-replay-demo.webm"
NARRATION = ROOT / "evidence" / "dev-week" / "controlx-authenticated-replay-demo-narration.txt"
OUTPUT_DIR = ROOT / "output" / "demo"
SEGMENTS_DIR = OUTPUT_DIR / "controlx-voice-natural-segments"
RAW_VOICE = OUTPUT_DIR / "controlx-authenticated-replay-demo-voice-natural-unpaced.wav"
VOICE = OUTPUT_DIR / "controlx-authenticated-replay-demo-voice-natural.wav"
OUTPUT = OUTPUT_DIR / "controlx-authenticated-replay-demo.mp4"
VOICE_NAME = os.environ.get("CONTROLX_DEMO_VOICE", "en-US-AvaMultilingualNeural")
VOICE_RATE = os.environ.get("CONTROLX_DEMO_VOICE_RATE", "-2%")
VOICE_PITCH = os.environ.get("CONTROLX_DEMO_VOICE_PITCH", "-2Hz")


def duration_seconds(ffmpeg: str, media: Path) -> float:
    probe = subprocess.run(
        [ffmpeg, "-hide_banner", "-i", str(media)],
        capture_output=True,
        text=True,
    )
    match = re.search(r"Duration: (\d+):(\d+):(\d+(?:\.\d+)?)", probe.stderr)
    if not match:
        raise SystemExit(f"Could not determine media duration: {media}")
    hours, minutes, seconds = match.groups()
    return int(hours) * 3600 + int(minutes) * 60 + float(seconds)


async def render_voice_segments(paragraphs: list[str]) -> list[Path]:
    SEGMENTS_DIR.mkdir(parents=True, exist_ok=True)
    segments: list[Path] = []
    for index, paragraph in enumerate(paragraphs, 1):
        destination = SEGMENTS_DIR / f"{index:02d}.mp3"
        for attempt in range(1, 4):
            try:
                await edge_tts.Communicate(
                    paragraph,
                    VOICE_NAME,
                    rate=VOICE_RATE,
                    pitch=VOICE_PITCH,
                ).save(str(destination))
                if destination.stat().st_size < 1_000:
                    raise RuntimeError("rendered segment is unexpectedly small")
                break
            except Exception:
                if attempt == 3:
                    raise
                await asyncio.sleep(attempt)
        segments.append(destination)
    return segments


def main() -> int:
    for required in (VIDEO, NARRATION):
        if not required.is_file():
            raise SystemExit(f"Missing required demo source: {required}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    paragraphs = [
        paragraph.strip()
        for paragraph in NARRATION.read_text().strip().split("\n\n")
        if paragraph.strip()
    ]
    segments = asyncio.run(render_voice_segments(paragraphs))

    inputs: list[str] = []
    for segment in segments:
        inputs.extend(["-i", str(segment)])
    concat = "".join(f"[{index}:a]" for index in range(len(segments)))
    concat += f"concat=n={len(segments)}:v=0:a=1[a]"
    subprocess.run(
        [
            ffmpeg,
            "-y",
            "-loglevel",
            "warning",
            *inputs,
            "-filter_complex",
            concat,
            "-map",
            "[a]",
            "-c:a",
            "pcm_s16le",
            str(RAW_VOICE),
        ],
        check=True,
    )

    tempo = duration_seconds(ffmpeg, RAW_VOICE) / duration_seconds(ffmpeg, VIDEO)
    if not 0.5 <= tempo <= 2.0:
        raise SystemExit(f"Narration tempo {tempo:.3f} is outside FFmpeg's safe range")
    subprocess.run(
        [
            ffmpeg,
            "-y",
            "-loglevel",
            "warning",
            "-i",
            str(RAW_VOICE),
            "-af",
            f"atempo={tempo:.6f},loudnorm=I=-16:TP=-1.5:LRA=7,aresample=48000",
            "-c:a",
            "pcm_s16le",
            str(VOICE),
        ],
        check=True,
    )
    subprocess.run(
        [
            ffmpeg,
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
            "18",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
            "-b:a",
            "192k",
            "-ar",
            "48000",
            "-shortest",
            "-movflags",
            "+faststart",
            str(OUTPUT),
        ],
        check=True,
    )
    print(f"voice={VOICE_NAME} rate={VOICE_RATE} pitch={VOICE_PITCH} tempo={tempo:.6f}")
    print(OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
