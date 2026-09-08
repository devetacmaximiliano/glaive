"""Generación de PDF — determinística, sin LLM.

``engine.py`` es el motor reportlab de Devetac (vendorizado desde
Reportes Pentesting/_template/generate_report.py, branding intacto).
``mapper.py`` arma el dict que ese motor espera a partir del ``Store`` de
glaive. Se dispara SOLO cuando el usuario lo pide explícitamente (comando
``/pdf`` en la sesión interactiva, o ``glaive report --pdf``) — nunca
automático.
"""
