#!/usr/bin/env python3

import subprocess


class FFmpeg:
    input: str
    output: str
    format: str
    bitrate: int | None
    fpass: tuple[int, int] | None

    def __init__(
        self,
        input="pipe:0",
        output="pipe:1",
        format="amr",
        bitrate=None,
        fpass=None,
    ):
        self.input = input
        self.output = output
        self.format = format
        self.bitrate = bitrate
        self.fpass = fpass

    def __get_cmd(self) -> list[str]:
        cmd = [
            "ffmpeg",
            "-i",
            self.input,
            "-f",
            self.format,
            "-ac",
            "1",
            "-ar",
            "8000",
        ]

        if self.bitrate is not None:
            cmd += ["-b:a", str(self.bitrate)]
        if self.fpass:
            cmd += [
                "-filter:a",
                f"highpass=f={self.fpass[0]},lowpass=f={self.fpass[1]}",
            ]
        return cmd + [self.output]

    def run(self):
        cmd = self.__get_cmd()

        subprocess.Popen(cmd)


def main():
    ff = FFmpeg(bitrate=12200, fpass=[200, 3400])
    ff.run()


if __name__ == "__main__":
    main()
