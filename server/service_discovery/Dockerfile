FROM golang:1.16 as build
ENV BUILDDIR=/buildsd
ENV GOPROXY=https://goproxy.cn,direct
ENV CGO_ENABLED=0
COPY . ${BUILDDIR}
WORKDIR ${BUILDDIR}
RUN mkdir -p dist/conf
RUN go build -o dist/sd main.go
COPY conf/* dist/conf/

# run
FROM alpine:3.14
ENV RUNDIR=/service_discovery
COPY --from=build /buildsd/dist ${RUNDIR}
WORKDIR ${RUNDIR}
ENTRYPOINT [ "./sd" ]
