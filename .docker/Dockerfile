FROM golang:1.22.4-alpine

WORKDIR /app

RUN go install github.com/air-verse/air@latest

ARG workdir

WORKDIR /app/${workdir}

CMD ["air"]
