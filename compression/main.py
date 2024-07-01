#!/usr/bin/env python3

import subprocess


class FFmpeg:
    input: str
    output: str
    format: str
    bitrate: str | None
    freq: int | None

    def __init__(
        self,
        input="pipe:0",
        output="pipe:1",
        format="mp3",
        bitrate=None,
        freq=None,
    ):
        self.input = input
        self.output = output
        self.format = format
        self.bitrate = bitrate
        self.freq = freq

    def __get_cmd(self) -> list[str]:
        cmd = ["ffmpeg", "-i", self.input, "-f", self.format, self.output]

        if self.bitrate is not None:
            cmd += ["-b:a", self.bitrate]
        if self.freq is not None:
            cmd += ["-ar", str(self.freq)]
        return cmd

    def run(self):
        cmd = self.__get_cmd()

        subprocess.Popen(cmd)


def main():
    ff = FFmpeg(bitrate="128k", freq=8000)
    ff.run()


if __name__ == "__main__":
    main()
