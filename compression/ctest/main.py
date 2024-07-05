import ctypes


def avcodec_version():
    f = ctypes.CDLL("libavcodec.so")

    print(f.avcodec_version())


def main():
    avcodec_version()


if __name__ == "__main__":
    main()
