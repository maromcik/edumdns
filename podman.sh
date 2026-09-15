
podman build -t registry.hafka.eu/edumdns-image .


podman push registry.hafka.eu/edumdns-image

ssh services@server systemctl --user restart edumdns.service
