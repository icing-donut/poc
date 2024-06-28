#!/usr/bin/env python3

import sys

from ffmpy import FFmpeg


def main():
    ff = FFmpeg(
        inputs={"pipe:0": None},
        outputs={"pipe:1": "-ar 8000 -b:a 128k -f mp3"},
    )
    ff.run(input_data=sys.stdin.buffer.read())


if __name__ == "__main__":
    main()
