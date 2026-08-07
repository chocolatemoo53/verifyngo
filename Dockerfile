# --- build stage ---
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
# CGO off + static binary: works unmodified in the scratch/distroless runtime below
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/verifyngo .

# --- runtime stage ---
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build --chown=nonroot:nonroot /out/verifyngo /app/verifyngo
# Baked in as a default/example; almost always overridden by a bind mount
# or a docker secret at deploy time -- see docker-compose.yml. Lives at the
# root, NOT under /app -- mounting a single file onto a path inside WORKDIR
# is what causes the "not a directory" bind-mount error if the host path
# doesn't exist yet. /config.json, /static, and /rules.txt are all
# top-level so they never collide with anything under /app.
COPY --chown=nonroot:nonroot config.example.json /config.json

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/app/verifyngo"]
CMD ["-config", "/config.json"]
