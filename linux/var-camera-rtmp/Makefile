

all:

	@echo "camera-rtmp"

x64:

	libtool --mode=link gcc `pkg-config --cflags --libs gstreamer-1.0` -o camrtmp.out main.c

arm:

	libtool --mode=link gcc `pkg-config --cflags --libs gstreamer-1.0` -o camrtmp.out arm.c

clean:

	rm -r *.out *.webm
