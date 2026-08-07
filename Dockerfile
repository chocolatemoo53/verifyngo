# --- build stage ---
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/verifyngo .

# --- runtime stage ---
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build --chown=nonroot:nonroot /out/verifyngo /app/verifyngo
COPY --chown=nonroot:nonroot /examples/config.json /config.json

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/app/verifyngo"]
CMD ["-config", "/config.json"]
