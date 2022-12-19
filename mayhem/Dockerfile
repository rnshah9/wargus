FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config libz-dev clang

COPY . /repo
WORKDIR /repo
RUN g++ pudconvert.cpp pud.cpp -lz -o pudconvert
RUN clang++ /repo/mayhem/fuzz_Parse.cpp -fsanitize=fuzzer,address -I /repo/ pud.cpp -lz -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /repo/pudconvert /
COPY --from=builder /fuzz /fuzz_Parse
