FROM node:20-alpine3.20

WORKDIR /tmp

COPY start.sh ./

EXPOSE 3000

RUN apk update && apk add --no-cache bash openssl curl tar gcompat &&\
    chmod +x start.sh

# ech-img.playingapi.tech
CMD ["./start.sh", "eyJhIjoiODllMDYzZWYxOGQ3ZmVjZjhlY2E2NTBiYWFjNzZjYmYiLCJ0IjoiZDg4ZjU5OTctZGE3Mi00MzNmLWE5NGUtNGY5MjcyOWU3NTYwIiwicyI6Ik1UZ3dZalU0T1RVdE5qVTJOQzAwTmpJeExXSTJaak10TVRnNU5UazRaVEZqTVRJMCJ9"]
