# Imagen de sandbox para glaive.
#
# Kali como base (repos y utilidades del ecosistema), pero con un toolkit
# CURADO — no el metapaquete completo (kali-linux-headless pesa varios GB).
# La idea es cubrir lo que se usa en la gran mayoría de un engagement web sin
# instalar nada de más; si el agente necesita algo puntual fuera de esta lista,
# lo instala él mismo con exec_command (ya lo hace bien: cloudscraper, etc).
#
# Se construye una sola vez — glaive.sandbox la arma sola si no existe — y
# después Docker cachea las capas, así que arranca al instante.
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl wget ca-certificates \
      nmap \
      dnsutils whois \
      jq git netcat-traditional \
      sqlmap nikto gobuster ffuf \
      python3 python3-pip python3-requests python3-cloudscraper python3-bs4 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
