FROM golang:1.16 as build
ENV BUILDDIR=/buildac
ENV GOPROXY=https://goproxy.cn,direct
COPY . ${BUILDDIR}
WORKDIR ${BUILDDIR}
RUN mkdir -p dist/conf
RUN mkdir -p dist/log
RUN go build -o dist/ac main.go
COPY conf/* dist/conf/

# run
FROM alpine:3.14
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
ENV RUNDIR=/agent_center
COPY --from=build /buildac/dist ${RUNDIR}
WORKDIR ${RUNDIR}
ENTRYPOINT [ "./ac" ]
