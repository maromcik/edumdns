#podman login cerit.io
podman build -t 192.168.0.10:5000/edumdns-image .
#podman tag 192.168.1.10:5000/edumdns-image cerit.io/roman_alexander_mariancik/edumdns-image
#podman push cerit.io/roman_alexander_mariancik/edumdns-image:latest
podman push 192.168.0.10:5000/edumdns-image
ssh roman@server systemctl --user restart edumdns.service
# ssh roman@hp systemctl --user restart edumdns.service
#kubectl apply -f kubernetes/edumdns -n mariancik-ns