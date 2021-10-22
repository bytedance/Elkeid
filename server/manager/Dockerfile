FROM golang:1.16 as build
ENV BUILDDIR=/buildmg
ENV GOPROXY=https://goproxy.cn,direct
ENV CGO_ENABLED=0
COPY . ${BUILDDIR}
WORKDIR ${BUILDDIR}
RUN mkdir -p dist/conf
RUN mkdir -p dist/log
RUN go build -o dist/mg main.go
RUN go build -o dist/init init.go
COPY conf/* dist/conf/

# run
FROM alpine:3.14
ENV RUNDIR=/manager
COPY --from=build /buildmg/dist ${RUNDIR}
WORKDIR ${RUNDIR}
ENTRYPOINT [ "./mg" ]
