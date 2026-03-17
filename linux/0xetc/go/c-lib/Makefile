all:

	@echo "build-a : build statically linked program"
	@echo "build-so: build dynamically linked program"

build-a:

	go build -tags=static -o c2go.out .


build-so:

	go build -tags=dynamic -o c2go.out .


clean:

	rm -rf *.out