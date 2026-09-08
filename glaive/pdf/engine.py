#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
Devetac - Pentesting Report Generator v2.0
================================================================================
Genera un PDF profesional de auditoría de seguridad con branding de Devetac.
Diseño modernizado basado en el template Laraigo.

DEPENDENCIAS:
    pip install reportlab pillow

USO:
    python3 generate_report.py
================================================================================
"""
import os
import sys
from datetime import datetime

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

try:
    from PIL import Image as PILImage
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False

# --- Verificar dependencias ---
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor, Color
    from reportlab.platypus import (
        SimpleDocTemplate, BaseDocTemplate, PageTemplate, Frame,
        NextPageTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, KeepTogether
    )
    from reportlab.platypus.flowables import Flowable
    from reportlab.platypus.tableofcontents import TableOfContents
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen import canvas
except ImportError:
    print("[ERROR] reportlab no encontrado.")
    print("Instalar con: pip install reportlab pillow")
    sys.exit(1)


# ============================================================================
# CONFIGURACION DEL REPORTE: el contenido sale de findings.yaml (no editar aca)
# ============================================================================

# REPORT_DATA: fallback minimo y neutro (sin datos de cliente).
# El flujo real lee 04_hallazgos/findings.yaml (vista generada por pentest_engine.py).
# Este dict solo se usa si findings.yaml no existe.
# Nota: el reporte se arma desde 04_hallazgos/findings.yaml (vista generada por pentest_engine.py).

# ============================================================================
# CONSTANTES DE DISEÑO
# ============================================================================

C_PRIMARY    = HexColor('#0E94A8')  # cyan-deep
C_SECONDARY  = HexColor('#2BD3E8')  # cyan
C_DARK_BG    = HexColor('#0A1626')  # ink
C_DARK_BG2   = HexColor('#122B45')  # surface
C_TEXT_LIGHT = HexColor('#E6EEF5')  # fog
C_TEXT_MUTED = HexColor('#495057') # Modern dark grey
C_WHITE      = HexColor('#FFFFFF')
C_LINE       = HexColor('#DCE6EE')  # hairline claro
C_BG_PAGE    = HexColor('#F8F9FA') # Page background
C_CARD_BG    = HexColor('#FFFFFF') # Card background
C_CVSS_BG    = HexColor('#E9ECEF') # CVSS block background
C_VERIFIED   = HexColor('#2E7D32') # Sobrio green

SEV = {
    "critico": {"label": "CRÍTICO", "color": HexColor('#F2555A'), "bg": HexColor('#FDEDEE')},
    "alto":    {"label": "ALTO",    "color": HexColor('#F59E42'), "bg": HexColor('#FEF2E6')},
    "medio":   {"label": "MEDIO",   "color": HexColor('#C99A1F'), "bg": HexColor('#FBF4DC')},
    "bajo":    {"label": "BAJO",    "color": HexColor('#5BA8E6'), "bg": HexColor('#E9F2FB')},
    "info":    {"label": "INFO",    "color": HexColor('#6E8499'), "bg": HexColor('#EDF1F4')},
}
SEV_ORDER = ["critico", "alto", "medio", "bajo", "info"]

PHASE = {
    "initial_access":    {"label": "Acceso Inicial",        "color": HexColor('#B71C1C')},
    "credential_harvest":{"label": "Cosecha de Credenciales","color": HexColor('#E65100')},
    "lateral_movement":  {"label": "Movimiento Lateral",    "color": HexColor('#4A148C')},
    "data_exfiltration": {"label": "Exfiltracion de Datos", "color": HexColor('#0D47A1')},
    "surface_expansion": {"label": "Expansion de Superficie","color": HexColor('#1B5E20')},
}
PHASE_ORDER = ["initial_access", "credential_harvest", "lateral_movement", "data_exfiltration", "surface_expansion"]

CONFIDENCE = {
    "alta":  {"label": "Confianza: Alta",  "color": HexColor('#2E7D32')},
    "media": {"label": "Confianza: Media", "color": HexColor('#F57F17')},
    "baja":  {"label": "Confianza: Baja",  "color": HexColor('#455A64')},
}

W, H = A4
MARGIN_L  = 18 * mm
MARGIN_R  = 18 * mm
MARGIN_T  = 20 * mm
MARGIN_B  = 20 * mm
CONTENT_W = W - MARGIN_L - MARGIN_R

# Vendorizado desde Reportes Pentesting/_template/generate_report.py — motor
# reportlab intacto (branding Devetac), solo cambian las rutas: assets propios
# de glaive en vez de la carpeta compartida _template/pdf_template. No hay
# carpeta de evidencia con imágenes (glaive no adjunta capturas al finding).
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR  = os.path.join(SCRIPT_DIR, "assets")
OUTPUT_DIR    = None  # el caller de generate_report() decide el output_path
LOGO_PATH     = os.path.join(TEMPLATE_DIR, "devetac_logo.png")
# Ruta deliberadamente inexistente: el código de imágenes por hallazgo hace
# os.path.isdir(EVIDENCIA_DIR/<id>) con el id SIEMPRE presente (fallback de
# evidence_folder) — None ahí rompería os.path.join. Con una ruta que nunca
# existe, isdir() da False y esa sección simplemente no agrega imágenes.
EVIDENCIA_DIR = os.path.join(SCRIPT_DIR, "_sin_evidencia_de_imagenes")

# ============================================================================
# FUENTES
# ============================================================================

def register_fonts():
    """Prefiere la tipografia de marca Devetac (Space Grotesk display + Inter body + IBM Plex Mono).
    Si esos .ttf no estan en pdf_template/, cae a Montserrat, y en ultimo caso a Helvetica.
    Para activar la marca, dejar en pdf_template/: SpaceGrotesk-Bold.ttf, SpaceGrotesk-SemiBold.ttf,
    Inter-Regular.ttf, Inter-Bold.ttf, Inter-Light.ttf, IBMPlexMono-Regular.ttf."""
    def reg(name, fname):
        path = os.path.join(TEMPLATE_DIR, fname)
        if not os.path.exists(path):
            return False
        try:
            pdfmetrics.registerFont(TTFont(name, path))
            return True
        except Exception as e:
            print(f"[!] Error registrando {name}: {e}")
            return False

    # 1) Marca Devetac: Space Grotesk (display) + Inter (body) + IBM Plex Mono
    have_display = reg("Display-Bold", "SpaceGrotesk-Bold.ttf") and reg("Display-SemiBold", "SpaceGrotesk-SemiBold.ttf")
    have_body = reg("Body", "Inter-Regular.ttf")
    have_body_bold = reg("Body-Bold", "Inter-Bold.ttf")
    have_body_light = reg("Body-Light", "Inter-Light.ttf")
    have_mono = reg("Mono", "IBMPlexMono-Regular.ttf")
    if have_display and have_body:
        pdfmetrics.registerFontFamily(
            "Body", normal="Body",
            bold="Body-Bold" if have_body_bold else "Display-Bold",
            italic="Body", boldItalic="Display-Bold",
        )
        print("[+] Fuentes Devetac cargadas (Space Grotesk + Inter + IBM Plex Mono)")
        return ("Body", "Display-Bold", "Display-SemiBold",
                "Body-Light" if have_body_light else "Body",
                "Mono" if have_mono else "Courier")

    # 2) Fallback: Montserrat (incluido en el template)
    font_map = {
        "Montserrat":          "Montserrat-Regular.ttf",
        "Montserrat-Bold":     "Montserrat-Bold.ttf",
        "Montserrat-SemiBold": "Montserrat-SemiBold.ttf",
        "Montserrat-Light":    "Montserrat-Light.ttf",
    }
    ok = [name for name, fname in font_map.items() if reg(name, fname)]
    if "Montserrat" in ok:
        pdfmetrics.registerFontFamily(
            "Montserrat", normal="Montserrat", bold="Montserrat-Bold",
            italic="Montserrat", boldItalic="Montserrat-Bold",
        )
        print(f"[+] Fuentes Montserrat cargadas (fallback, {len(ok)} variaciones). "
              "Para la marca Devetac, agregar Space Grotesk + Inter a pdf_template/.")
        return ("Montserrat", "Montserrat-Bold", "Montserrat-SemiBold", "Montserrat-Light",
                "Mono" if have_mono else "Courier")

    # 3) Ultimo recurso
    print("[!] FALLBACK: Usando Helvetica (el diseño de tablas puede verse afectado)")
    return "Helvetica", "Helvetica-Bold", "Helvetica-Bold", "Helvetica", "Courier"

FONT_REG, FONT_BOLD, FONT_SEMI, FONT_LIGHT, FONT_MONO = register_fonts()

# ============================================================================
# ESTILOS
# ============================================================================

def build_styles():
    s = {}
    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    s['cover_title']   = ps('cover_title',   fontName=FONT_BOLD,  fontSize=26, textColor=C_WHITE,     spaceAfter=6,  leading=32, alignment=TA_LEFT)
    s['cover_sub']     = ps('cover_sub',     fontName=FONT_SEMI,  fontSize=14, textColor=C_SECONDARY,  spaceAfter=4,  leading=18, alignment=TA_LEFT)
    s['section_title'] = ps('section_title', fontName=FONT_BOLD,  fontSize=17, textColor=C_PRIMARY,    spaceBefore=6, spaceAfter=5, leading=21)
    s['subsect']       = ps('subsect',       fontName=FONT_SEMI,  fontSize=11, textColor=HexColor('#1A1A2E'), spaceBefore=8, spaceAfter=4, leading=15)
    s['body']          = ps('body',          fontName=FONT_REG,   fontSize=9.5,textColor=HexColor('#2C2C3E'), spaceAfter=4, leading=15, alignment=TA_JUSTIFY)
    s['table_hdr']     = ps('table_hdr',     fontName=FONT_BOLD,  fontSize=8.5,textColor=C_WHITE,      alignment=TA_LEFT, leading=12)
    s['table_cell']    = ps('table_cell',    fontName=FONT_REG,   fontSize=8.5,textColor=HexColor('#2C2C3E'), alignment=TA_LEFT, leading=12)
    s['caption']       = ps('caption',       fontName=FONT_LIGHT, fontSize=7.5,textColor=C_TEXT_MUTED, alignment=TA_CENTER, leading=10)
    s['bullet']        = ps('bullet',        fontName=FONT_REG,   fontSize=9,  textColor=HexColor('#2C2C3E'), spaceAfter=3, leading=14, leftIndent=10)
    s['toc_entry']     = ps('toc_entry',     fontName=FONT_REG,   fontSize=9.5,textColor=HexColor('#2C2C3E'), spaceAfter=5, leading=14)
    s['toc_level1']    = ps('toc_level1',    fontName=FONT_REG,   fontSize=9.5,textColor=HexColor('#2C2C3E'), spaceAfter=4, leading=14, leftIndent=0)
    s['code_p']        = ps('code_p',        fontName=FONT_MONO,  fontSize=7.5,textColor=HexColor('#C9D1D9'), leading=12, leftIndent=6, rightIndent=6)
    s['ioc_title']     = ps('ioc_title',     fontName=FONT_BOLD,  fontSize=9,  textColor=C_WHITE, leading=13)
    s['sig']           = ps('sig',           fontName=FONT_SEMI,  fontSize=8.5,textColor=C_TEXT_MUTED, alignment=TA_CENTER, leading=13)
    return s

# ============================================================================
# FLOWABLES PERSONALIZADOS
# ============================================================================

class DividerLine(Flowable):
    def __init__(self, width, color=None, thickness=1.5):
        super().__init__()
        self.width = width
        self.color = color or C_PRIMARY
        self.thickness = thickness
        self.height = thickness + 4

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, self.thickness / 2, self.width, self.thickness / 2)


class SeverityBar(Flowable):
    def __init__(self, level, count, max_count, width):
        super().__init__()
        self.level     = level
        self.count     = count
        self.max_count = max_count
        self.width     = width
        self.height    = 28

    def draw(self):
        c = self.canv
        s = SEV[self.level]
        bar_zone = self.width - 110
        bar_w    = (self.count / max(self.max_count, 1)) * bar_zone if self.count else 0
        mid      = self.height / 2

        # Dot
        c.setFillColor(s['color'])
        c.circle(7, mid, 5, fill=1, stroke=0)
        # Label
        c.setFillColor(HexColor('#1A1A2E'))
        c.setFont(FONT_SEMI, 9)
        c.drawString(17, mid - 4, s['label'])
        # Track
        c.setFillColor(HexColor('#EBEBF5'))
        c.roundRect(90, mid - 5, bar_zone, 10, 4, fill=1, stroke=0)
        # Fill
        if bar_w > 0:
            c.setFillColor(s['color'])
            c.roundRect(90, mid - 5, bar_w, 10, 4, fill=1, stroke=0)
        # Count
        c.setFillColor(HexColor('#1A1A2E'))
        c.setFont(FONT_BOLD, 10)
        c.drawRightString(self.width, mid - 4, str(self.count))


class FindingHeader(Flowable):
    def __init__(self, fid, title, severity, width, phase=None, confidence=None):
        super().__init__()
        self.fid        = fid
        self.title      = title
        self.severity   = severity
        self.width      = width
        self.phase      = phase
        self.confidence = confidence
        self.height     = 72

    def wrap(self, availWidth, availHeight):
        # Calculate dynamic height based on title wrap
        bx = 15
        bw = 64
        text_x = bx + bw + 15
        ph = PHASE.get(self.phase) if self.phase else None
        if ph:
            pw = len(ph['label']) * 5.2 + 12
            text_x = bx + bw + 8 + pw + 12
        
        p_style = ParagraphStyle('fh_t', fontName=FONT_BOLD, fontSize=11, textColor=C_DARK_BG, leading=13)
        p = Paragraph(self.title, p_style)
        
        # Room for confidence badge if it exists
        conf_w = 0
        cf = CONFIDENCE.get(self.confidence) if self.confidence else None
        if cf:
            conf_w = len(cf['label']) * 5.2 + 25
            
        w_p, h_p = p.wrap(availWidth - text_x - conf_w - 15, availHeight)
        self.height = max(72, h_p + 42)
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        s = SEV.get(self.severity, SEV["info"])
        h = self.height

        # Card Shadow (Using Color instead of HexColor for alpha compatibility)
        c.setFillColor(Color(0, 0, 0, alpha=0.03))
        c.roundRect(1, -1.5, self.width, h, 6, fill=1, stroke=0)
        
        # Primary Card
        c.setFillColor(C_CARD_BG)
        c.setStrokeColor(C_LINE)
        c.setLineWidth(0.6)
        c.roundRect(0, 0, self.width, h, 6, fill=1, stroke=1)

        # Left Branding Bar
        c.setFillColor(s['color'])
        c.roundRect(0, 0, 5, h, 3, fill=1, stroke=0)
        c.rect(2.5, 0, 2.5, h, fill=1, stroke=0)

        # Badges Row
        by = h - 25
        bx = 15
        
        # 1. Severity Badge
        bw = 64
        c.setFillColor(s['color'])
        c.roundRect(bx, by, bw, 16, 5, fill=1, stroke=0)
        c.setFillColor(C_WHITE)
        c.setFont(FONT_BOLD, 7.5)
        c.drawCentredString(bx + bw / 2, by + 5, s['label'])
        
        # 2. Phase Badge
        text_x = bx + bw + 15
        ph = PHASE.get(self.phase) if self.phase else None
        if ph:
            ph_label = ph['label']
            pw = len(ph_label) * 5.2 + 12
            px = bx + bw + 8
            c.setStrokeColor(ph['color'])
            c.setLineWidth(0.8)
            c.roundRect(px, by, pw, 16, 5, fill=0, stroke=1)
            c.setFillColor(ph['color'])
            c.setFont(FONT_SEMI, 6.5)
            c.drawCentredString(px + pw / 2, by + 5, ph_label)
            text_x = px + pw + 12

        # 3. Confidence Badge
        conf_w = 0
        cf = CONFIDENCE.get(self.confidence) if self.confidence else None
        if cf:
            cw = len(cf['label']) * 5.2 + 12
            cx = self.width - cw - 15
            conf_w = cw + 15
            c.setStrokeColor(cf['color'])
            c.setLineWidth(0.8)
            c.roundRect(cx, by, cw, 16, 5, fill=0, stroke=1)
            c.setFillColor(cf['color'])
            c.setFont(FONT_SEMI, 6.5)
            c.drawCentredString(cx + cw / 2, by + 5, cf['label'])

        # ID and Title
        c.setFillColor(C_TEXT_MUTED)
        c.setFont(FONT_REG, 8.5)
        c.drawString(text_x, h - 23, self.fid.upper())
        
        p_style = ParagraphStyle('fh_t', fontName=FONT_BOLD, fontSize=11, textColor=C_DARK_BG, leading=13)
        p = Paragraph(self.title, p_style)
        w_p, h_p = p.wrap(self.width - text_x - conf_w - 5, h)
        p.drawOn(c, text_x, h - 35 - h_p)


class CoverPage(Flowable):
    def __init__(self, data, logo_path, width, height):
        super().__init__()
        self.data      = data
        self.logo_path = logo_path
        self.width     = width
        self.height    = height

    def _draw_wireframe_globe(self, c, cx, cy, r):
        c.setStrokeColor(HexColor('#1E2A40')) 
        c.setLineWidth(0.4)
        c.circle(cx, cy, r, fill=0, stroke=1)
        for i in range(1, 4):
            c.ellipse(cx - r, cy - r*(0.25*i), cx + r, cy + r*(0.25*i))
        for i in range(1, 4):
            c.ellipse(cx - r*(0.25*i), cy - r, cx + r*(0.25*i), cy + r)

    def _draw_circuit(self, c, w, h):
        c.setStrokeColor(HexColor('#19253A'))
        c.setFillColor(HexColor('#19253A'))
        c.setLineWidth(0.6)
        
        ox, oy = w - 10*mm, 10*mm
        tracks = [
            [(ox, oy), (ox-20*mm, oy+20*mm), (ox-50*mm, oy+20*mm)],
            [(ox-10*mm, oy), (ox-30*mm, oy+20*mm), (ox-80*mm, oy+20*mm)],
            [(ox, oy+10*mm), (ox-20*mm, oy+30*mm), (ox-20*mm, oy+70*mm)],
            [(ox, oy+30*mm), (ox-20*mm, oy+50*mm), (ox-50*mm, oy+50*mm)],
            [(w-MARGIN_R, 60*mm), (w-MARGIN_R-20*mm, 40*mm), (w-MARGIN_R-40*mm, 40*mm)],
            [(w-MARGIN_R-10*mm, 80*mm), (w-MARGIN_R-30*mm, 60*mm), (w-MARGIN_R-60*mm, 60*mm)],
        ]
        
        for tr in tracks:
            path = c.beginPath()
            path.moveTo(*tr[0])
            for pt in tr[1:]:
                path.lineTo(*pt)
            c.drawPath(path)
            c.circle(tr[-1][0], tr[-1][1], 1.5, fill=1, stroke=0)

    def draw(self):
        c = self.canv
        d = self.data
        w = self.width
        h = self.height

        # 1. Base Background
        c.setFillColor(HexColor('#090E17'))
        c.rect(0, 0, w, h, fill=1, stroke=0)

        c.setFillColor(HexColor('#0D1424'))
        c.circle(w*0.8, h*0.8, 300, fill=1, stroke=0)

        # 2. Header
        hdr_h   = 52 * mm
        hdr_y   = h - hdr_h
        hdr_mid = hdr_y + hdr_h / 2

        c.setStrokeColor(HexColor('#1A2F4A'))
        c.setFillColor(HexColor('#1A2F4A'))
        c.setLineWidth(0.55)
        hdr_tracks = [
            [(w - 12*mm, h -  6*mm), (w - 38*mm, h - 26*mm), (w - 72*mm, h - 26*mm)],
            [(w - 22*mm, h -  6*mm), (w - 48*mm, h - 22*mm), (w - 85*mm, h - 22*mm)],
            [(w - 12*mm, h - 16*mm), (w - 30*mm, h - 34*mm), (w - 30*mm, hdr_y + 8*mm)],
            [(w - 40*mm, h -  6*mm), (w - 58*mm, h - 22*mm), (w - 58*mm, hdr_y + 6*mm)],
        ]
        for tr in hdr_tracks:
            path = c.beginPath()
            path.moveTo(*tr[0])
            for pt in tr[1:]:
                path.lineTo(*pt)
            c.drawPath(path)
            c.circle(tr[-1][0], tr[-1][1], 1.2, fill=1, stroke=0)

        self._draw_circuit(c, w, h)

        # 3. Logo
        logo_size = 38 * mm
        logo_x = MARGIN_L
        logo_y = hdr_mid - logo_size / 2

        if os.path.exists(self.logo_path):
            try:
                c.drawImage(self.logo_path, logo_x, logo_y,
                            width=logo_size, height=logo_size,
                            mask='auto', preserveAspectRatio=True)
            except Exception: pass

        # 4. Brand text
        brand_x = logo_x + logo_size + 8 * mm
        c.setFont(FONT_BOLD, 30)
        c.setFillColor(C_WHITE)
        c.drawString(brand_x, hdr_mid + 5 * mm, "Devetac")

        bar_h = 9 * mm
        bar_y = hdr_mid - 8 * mm
        c.setFillColor(HexColor('#6C4FC9'))
        c.rect(brand_x, bar_y, 2.5, bar_h, fill=1, stroke=0)
        c.setFont(FONT_REG, 8.5)
        c.setFillColor(HexColor('#5A7BAC'))
        c.drawString(brand_x + 5 * mm, hdr_mid - 5 * mm, "OFFENSIVE SECURITY")

        # 5. Confidential Badge
        tag_w = 60 * mm
        tag_h =  7 * mm
        tag_x = MARGIN_L
        tag_y = h - 61 * mm 

        # Suble glow
        for i in range(3, 0, -1):
            c.setFillColor(HexColor('#180408'))
            c.roundRect(tag_x - i*0.8, tag_y - i*0.8,
                        tag_w + i*1.6, tag_h + i*1.6, 1.2*mm, fill=1, stroke=0)

        c.setFillColor(HexColor('#0F0306'))
        c.roundRect(tag_x, tag_y, tag_w, tag_h, 1.2*mm, fill=1, stroke=0)
        c.setStrokeColor(HexColor('#C41230'))
        c.setLineWidth(0.7)
        c.roundRect(tag_x, tag_y, tag_w, tag_h, 1.2*mm, fill=0, stroke=1)

        tri_cx = tag_x + 5.5 * mm
        tri_cy = tag_y + tag_h / 2
        tri_h  = 3.2 * mm
        tri_w  = 3.6 * mm
        tri_path = c.beginPath()
        tri_path.moveTo(tri_cx,           tri_cy + tri_h * 0.58)
        tri_path.lineTo(tri_cx - tri_w/2, tri_cy - tri_h * 0.42)
        tri_path.lineTo(tri_cx + tri_w/2, tri_cy - tri_h * 0.42)
        tri_path.close()
        c.setFillColor(HexColor('#E11D48'))
        c.drawPath(tri_path, fill=1, stroke=0)
        c.setFillColor(HexColor('#0F0306'))
        c.setFont(FONT_BOLD, 3.8)
        c.drawCentredString(tri_cx, tri_cy - 1.0 * mm, "!")

        sep_x = tag_x + 9.5 * mm
        c.setStrokeColor(HexColor('#4A0E1A'))
        c.setLineWidth(0.5)
        c.line(sep_x, tag_y + 1.5*mm, sep_x, tag_y + tag_h - 1.5*mm)
        c.setFillColor(HexColor('#F9A8B8'))
        c.setFont(FONT_SEMI, 6)
        text_cx = sep_x + (tag_x + tag_w - sep_x) / 2
        c.drawCentredString(text_cx, tag_y + 2.2 * mm, "CONFIDENCIAL / ACCESO CLIENTE")

        # 6. Main Title
        title_y = h * 0.60
        c.setFont(FONT_REG, 11)
        c.setFillColor(C_WHITE)
        c.drawString(MARGIN_L, title_y, "EVALUACIÓN DE")

        title_y -= 40*mm
        c.setFont(FONT_BOLD, 76)
        c.setFillColor(C_WHITE)
        c.drawString(MARGIN_L - 3, title_y, "SEGURIDAD")

        title_y -= 26*mm
        c.setFont(FONT_LIGHT, 56)
        c.setFillColor(C_WHITE)
        c.drawString(MARGIN_L, title_y, "OFENSIVA")

        div_y = title_y - 25*mm
        c.setStrokeColor(HexColor('#2E3C56')) 
        c.setLineWidth(1)
        c.line(MARGIN_L, div_y, w - MARGIN_R, div_y)
        
        # 7. Grid Layout
        g_y = div_y - 15*mm
        col1_x = MARGIN_L
        col2_x = MARGIN_L + 65*mm
        col3_x = MARGIN_L + 120*mm

        LC = HexColor('#6681AF') 
        VC = C_WHITE

        # Row 1
        r1_y = g_y
        c.setFont(FONT_REG, 7)
        c.setFillColor(LC)
        c.drawString(col1_x, r1_y, "TIPO DE EVALUACIÓN")
        c.drawString(col2_x, r1_y, "METODOLOGÍA")
        c.drawString(col3_x, r1_y, "VERSIÓN")

        r1_vy = r1_y - 5*mm
        c.setFont(FONT_REG, 9)
        c.setFillColor(VC)
        c.drawString(col1_x, r1_vy, d['engagement_type'])
        c.drawString(col2_x, r1_vy, d['methodology'])
        c.drawString(col3_x, r1_vy, d['version'])

        # Row 2
        r2_y = r1_vy - 12*mm 
        c.setFont(FONT_REG, 7)
        c.setFillColor(LC)
        c.drawString(col1_x, r2_y, "PREPARADO PARA:")
        c.drawString(col2_x, r2_y, "FECHA")
        
        c.setFont(FONT_BOLD, 28)
        c.setFillColor(C_WHITE)
        c.drawString(col1_x, r2_y - 12*mm, d['client_name'].upper())
        
        c.setFont(FONT_REG, 8.5)
        c.setFillColor(VC)
        c.drawString(col1_x, r2_y - 18*mm, d['client_industry'].upper())

        c.setFont(FONT_REG, 9)
        c.setFillColor(VC)
        c.drawString(col2_x, r2_y - 5*mm, d['report_date']) 

        # Row 3 (Scope)
        r3_y = r2_y - 32*mm
        c.setFont(FONT_REG, 7)
        c.setFillColor(LC)
        c.drawString(col1_x, r3_y, "ALCANCE PRINCIPAL:")

        c.setFont(FONT_REG, 8.5)
        c.setFillColor(VC)
        c.drawString(col1_x, r3_y - 5*mm, d['target_scope'])


# ============================================================================
# CANVAS CON HEADER / FOOTER
# ============================================================================

class ReportCanvas(canvas.Canvas):
    def __init__(self, filename, data, logo_path, **kwargs):
        super().__init__(filename, **kwargs)
        self._doc_data   = data
        self._logo_path  = logo_path
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_chrome(total)
            super().showPage()
        super().save()

    def _draw_chrome(self, total):
        # No header/footer on cover
        if self._pageNumber == 1:
            return
        d = self._doc_data
        self.saveState()

        # Header Moderno
        hy = H - 12 * mm
        self.setStrokeColor(C_PRIMARY)
        self.setLineWidth(1.2)
        self.line(MARGIN_L, hy, W - MARGIN_R, hy)
        
        # Thinner accent line
        self.setStrokeColor(C_SECONDARY)
        self.setLineWidth(0.4)
        self.line(MARGIN_L, hy - 0.8*mm, W - MARGIN_R, hy - 0.8*mm)

        if os.path.exists(self._logo_path):
            try:
                self.drawImage(self._logo_path, MARGIN_L, hy + 1.5*mm,
                               width=6*mm, height=6*mm,
                               mask='auto', preserveAspectRatio=True)
            except Exception: pass

        self.setFont(FONT_BOLD, 8)
        self.setFillColor(C_PRIMARY)
        self.drawString(MARGIN_L + 9*mm, hy + 2.8*mm, "Devetac")
        self.setFont(FONT_REG, 7.5)
        self.setFillColor(C_TEXT_MUTED)
        self.drawString(MARGIN_L + 32*mm, hy + 2.8*mm,
                        f"Auditoría Técnica  ·  {d['client_name']}  ·  Confidencial")

        # Footer Moderno
        fy = MARGIN_B - 10 * mm
        self.setStrokeColor(HexColor('#E5E7EB'))
        self.setLineWidth(0.6)
        self.line(MARGIN_L, fy + 12, W - MARGIN_R, fy + 12)
        
        self.setFont(FONT_LIGHT, 7.5)
        self.setFillColor(C_TEXT_MUTED)
        self.drawString(MARGIN_L, fy + 4,
                        f"Seguridad Ofensiva  ·  Devetac  ·  {d['report_date']}")
        self.drawRightString(W - MARGIN_R, fy + 4,
                             f"Página {self._pageNumber} de {total}")
        self.restoreState()


# ============================================================================
# DOC TEMPLATE WITH TOC SUPPORT
# ============================================================================

class ReportDocTemplate(BaseDocTemplate):
    def afterFlowable(self, flowable):
        if not isinstance(flowable, Paragraph):
            return
        style_name = getattr(flowable.style, 'name', '')
        if style_name != 'section_title':
            return
        text = flowable.getPlainText()
        if text.startswith('Índice'):
            return
        key = 'toc-' + text.replace(' ', '-')[:40]
        self.canv.bookmarkPage(key)
        self.notify('TOCEntry', (0, text, self.page, key))


# ============================================================================
# BUILDERS
# ============================================================================

def mk_table(rows, col_widths, style_overrides=None):
    base = [
        ('GRID',          (0,0),(-1,-1), 0.5, C_LINE),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('TOPPADDING',    (0,0),(-1,-1), 7),
        ('BOTTOMPADDING', (0,0),(-1,-1), 7),
        ('LEFTPADDING',   (0,0),(-1,-1), 10),
        ('RIGHTPADDING',  (0,0),(-1,-1), 8),
        ('FONTNAME',      (0,0),(-1,-1), FONT_REG),
        ('FONTSIZE',      (0,0),(-1,-1), 9),
    ]
    if style_overrides:
        base.extend(style_overrides)
    t = Table(rows, colWidths=col_widths)
    t.setStyle(TableStyle(base))
    return t


def section_header(title, styles):
    return [
        Paragraph(title, styles['section_title']),
        DividerLine(CONTENT_W, C_PRIMARY, 2),
        Spacer(1, 5*mm),
    ]


def build_cover(data, logo_path, styles):
    cover = CoverPage(data, logo_path, W, H)
    cover.hAlign = 'LEFT'
    return [cover]


def build_toc(data, styles):
    story = [
        Paragraph("Índice de Contenidos", styles['section_title']),
        DividerLine(CONTENT_W, C_PRIMARY, 2),
        Spacer(1, 5*mm),
    ]
    toc = TableOfContents()
    toc.dotsMinLevel = 0
    toc.levelStyles = [
        styles['toc_level1'],
    ]
    story.append(toc)
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        '',
        styles['caption']
    ))
    return story


def build_doc_details(data, styles):
    story = section_header("Detalles del Documento", styles)

    doc_rows = [
        [Paragraph('<b>Cliente</b>',         styles['table_cell']), Paragraph(data['client_name'],                                      styles['table_cell'])],
        [Paragraph('<b>Fecha de entrega</b>',styles['table_cell']), Paragraph(data.get('delivery_date', data['report_date']),            styles['table_cell'])],
        [Paragraph('<b>Clasificación</b>',   styles['table_cell']), Paragraph(data.get('doc_classification', 'CONFIDENCIAL'),            styles['table_cell'])],
        [Paragraph('<b>Tipo de documento</b>',styles['table_cell']),Paragraph(data.get('doc_type', 'Informe de Pentest'),                styles['table_cell'])],
        [Paragraph('<b>Versión</b>',         styles['table_cell']), Paragraph(data['version'],                                          styles['table_cell'])],
    ]
    story.append(mk_table(doc_rows, [50*mm, CONTENT_W - 50*mm],
                          [('BACKGROUND', (0,0),(0,-1), HexColor('#F0EEFF'))]))
    story.append(Spacer(1, 5*mm))

    proj_rows = [
        [Paragraph('<b>Tipo de evaluación</b>',   styles['table_cell']), Paragraph(data['engagement_type'],                              styles['table_cell'])],
        [Paragraph('<b>Metodología</b>',          styles['table_cell']), Paragraph(data['methodology'],                                  styles['table_cell'])],
        [Paragraph('<b>Período</b>',              styles['table_cell']), Paragraph(f"{data['start_date']} -> {data['end_date']}",        styles['table_cell'])],
        [Paragraph('<b>Analista responsable</b>', styles['table_cell']), Paragraph(data['auditor_name'],                                 styles['table_cell'])],
    ]
    story.append(mk_table(proj_rows, [50*mm, CONTENT_W - 50*mm],
                          [('BACKGROUND', (0,0),(0,-1), HexColor('#F0EEFF'))]))
    story.append(Spacer(1, 5*mm))

    recipients = data.get('doc_recipients', [])
    if recipients:
        story.append(Paragraph("Destinatarios", styles['subsect']))
        hdr = [[Paragraph("NOMBRE",  styles['table_hdr']),
                Paragraph("EMAIL",   styles['table_hdr']),
                Paragraph("CARGO",   styles['table_hdr']),
                Paragraph("EMPRESA", styles['table_hdr'])]]
        rows = hdr + [
            [Paragraph(r.get('name', ''),    styles['table_cell']),
             Paragraph(r.get('email', ''),   styles['table_cell']),
             Paragraph(r.get('role', ''),    styles['table_cell']),
             Paragraph(r.get('company', ''), styles['table_cell'])]
            for r in recipients
        ]
        story.append(mk_table(rows,
                              [45*mm, CONTENT_W - 45*mm - 30*mm - 40*mm, 30*mm, 40*mm],
                              [('BACKGROUND', (0,0),(-1,0), C_PRIMARY),
                               ('TEXTCOLOR',  (0,0),(-1,0), C_WHITE),
                               ('ROWBACKGROUNDS', (0,1),(-1,-1), [C_WHITE, HexColor('#F7F5FF')])]))
    return story


def build_cover_letter(data, styles):
    story = [
        Paragraph("<b>CARTA DE PRESENTACIÓN</b>", styles['section_title']),
        Spacer(1, 15*mm),
        Paragraph(f"Ciudad Autónoma de Buenos Aires, {data['report_date']}", styles['body']),
        Spacer(1, 10*mm),
        Paragraph("<b>A la Gerencia de Tecnología y Seguridad de la Información,</b>", styles['body']),
        Paragraph(f"<b>{data['client_name']} S.A.</b>", styles['body']),
        Spacer(1, 8*mm),
        Paragraph("Tengo el agrado de presentarle los resultados de la Auditoría de Seguridad Técnica (Pentesting) realizada sobre los activos digitales de la compañía. Este documento resume los hallazgos identificados, su criticidad técnica y el impacto potencial para el negocio.", styles['body']),
        Spacer(1, 4*mm),
        Paragraph("Nuestra evaluación se centró en identificar vectores de compromiso que pudieran afectar la confidencialidad de los datos de sus suscriptores y la integridad de los procesos financieros. Los resultados aquí presentados reflejan una 'foto' del estado de seguridad al momento de la prueba y deben ser abordados con la prioridad sugerida en el Plan de Remediación.", styles['body']),
        Spacer(1, 4*mm),
        Paragraph("Agradecemos la confianza depositada en Devetac para fortalecer la postura de seguridad de su organización. Quedamos a su entera disposición para cualquier aclaración técnica o soporte durante el proceso de remediación.", styles['body']),
        Spacer(1, 25*mm),
        Paragraph("Atentamente,", styles['body']),
        Spacer(1, 15*mm),
        Paragraph(f"<b>{data['auditor_name']}</b>", styles['body']),
        Paragraph(f"{data['auditor_role']} · Devetac", styles['body']),
    ]
    return story


def build_exec_summary(data, styles):
    story = section_header("01 - Resumen Ejecutivo", styles)
    
    # Dynamic Risk Score Calculation
    fc = data.get("findings_count", {})
    # Formula: (Altos * 2.4) + (Medios * 0.8) + (Impacto Regulatorio * 1.5)
    high_w = fc.get("alto", 0) * 2.4
    med_w  = fc.get("medio", 0) * 0.8
    reg_w  = 1.5 if fc.get("alto", 0) > 0 else 0 # Simple logic: High findings usually imply reg impact
    
    risk_score = min(10.0, high_w + med_w + reg_w)
    
    score_label = "CRÍTICO" if risk_score >= 7.5 else "ALTO" if risk_score >= 5.0 else "MEDIO" if risk_score >= 2.5 else "BAJO"
    score_color = "#D32F2F" if risk_score >= 7.5 else "#F57C00" if risk_score >= 5.0 else "#FBC02D" if risk_score >= 2.5 else "#388E3C"

    score_rows = [[
        Paragraph('<font size="14">Nivel de Riesgo General:</font>', styles['body']),
        Paragraph(f'<font size="24" color="{score_color}"><b>{risk_score:.1f} / 10</b></font>', styles['cover_title']),
        Paragraph(f'<font size="14" color="{score_color}"><b>{score_label}</b></font>', styles['cover_title'])
    ]]
    story.append(mk_table(score_rows, [CONTENT_W * 0.45, CONTENT_W * 0.25, CONTENT_W * 0.3], [('VALIGN', (0,0),(-1,-1), 'MIDDLE')]))
    story.append(Spacer(1, 10*mm))

    story.append(Paragraph(data["executive_narrative"], styles['body']))
    story.append(Spacer(1, 6*mm))

    story.append(Paragraph("Métricas de la Evaluación", styles['subsect']))
    rows = [
        [Paragraph(f'<b>{lbl}</b>', styles['table_cell']),
         Paragraph(f'<font color="#6E40C9"><b>{val}</b></font>',
                   ParagraphStyle('mv', fontName=FONT_BOLD, fontSize=11,
                                  textColor=C_PRIMARY, alignment=TA_CENTER, leading=14))]
        for lbl, val in data["executive_metrics"]
    ]
    story.append(mk_table(rows, [CONTENT_W * 0.7, CONTENT_W * 0.3],
                          [('ROWBACKGROUNDS', (0,0),(-1,-1), [HexColor('#FAFAFE'), HexColor('#F0EEFF')])]))
    story.append(Spacer(1, 6*mm))

    story.append(Paragraph("Lo que un atacante puede hacer hoy", styles['subsect']))
    for item in data["attacker_can_do"]:
        row = [[
            Paragraph('<font color="#C62828"><b>-</b></font>',
                      ParagraphStyle('ico', fontName=FONT_BOLD, fontSize=10,
                                     textColor=HexColor('#C62828'), alignment=TA_CENTER, leading=14)),
            Paragraph(item, styles['body'])
        ]]
        t = mk_table(row, [8*mm, CONTENT_W - 8*mm], [('GRID',(0,0),(-1,-1),0,C_WHITE)])
        story.append(t)
    story.append(Spacer(1, 6*mm))

    story.append(Paragraph("Acciones Inmediatas - 48 horas", styles['subsect']))
    hdr = [[Paragraph("ACCION", styles['table_hdr']),
            Paragraph("SISTEMA / DETALLE", styles['table_hdr']),
            Paragraph("RESPONSABLE", styles['table_hdr'])]]
    rows = hdr + [[Paragraph(f'<b>{v}</b>', styles['table_cell']),
                   Paragraph(d, styles['table_cell']),
                   Paragraph(r, styles['table_cell'])]
                  for v, d, r in data["immediate_actions"]]
    story.append(mk_table(rows, [22*mm, CONTENT_W - 52*mm, 30*mm],
                          [('BACKGROUND', (0,0),(-1,0), C_PRIMARY),
                           ('TEXTCOLOR',  (0,0),(-1,0), C_WHITE),
                           ('ROWBACKGROUNDS',(0,1),(-1,-1), [C_WHITE, HexColor('#F7F5FF')])]))
    story.append(Spacer(1, 6*mm))

    story.append(Paragraph("Exposición Legal y Regulatoria", styles['subsect']))
    hdr = [[Paragraph("MARCO", styles['table_hdr']),
            Paragraph("POR QUÉ APLICA", styles['table_hdr']),
            Paragraph("CONSECUENCIA", styles['table_hdr'])]]
    rows = hdr + [[Paragraph(f'<b>{m}</b>', styles['table_cell']),
                   Paragraph(a, styles['table_cell']),
                   Paragraph(c, styles['table_cell'])]
                  for m, a, c in data["legal_exposure"]]
    story.append(mk_table(rows, [35*mm, CONTENT_W * 0.42, CONTENT_W - 35*mm - CONTENT_W * 0.42],
                          [('BACKGROUND', (0,0),(-1,0), HexColor('#B71C1C')),
                           ('TEXTCOLOR',  (0,0),(-1,0), C_WHITE),
                           ('ROWBACKGROUNDS',(0,1),(-1,-1), [HexColor('#FFF8F8'), HexColor('#FFEBEE')])]))
    
    story.append(Spacer(1, 12*mm))
    story.append(DividerLine(CONTENT_W, HexColor('#EEEEEE'), 0.5))
    story.append(Paragraph(
        '<font size="8" color="#777777"><i>* Nota Metodológica: El Nivel de Riesgo General se calcula mediante la ponderación de hallazgos (Altos x 2.4, Medios x 0.8) más un factor de impacto regulatorio/financiero (x 1.5), normalizado en escala 0-10.</i></font>',
        styles['body']
    ))
    return story


def build_dashboard(data, styles):
    fc    = data["findings_count"]
    total = sum(fc.values())
    story = section_header("03 - Dashboard de Métricas y Severidad", styles)

    # Big counters row
    cells = []
    for sev in SEV_ORDER:
        cnt = fc.get(sev, 0)
        s   = SEV[sev]
        # Use a nested table for the card feel
        inner = Table(
            [[Paragraph(str(cnt), ParagraphStyle('bn', fontName=FONT_BOLD, fontSize=28,
                                                 textColor=s['color'], alignment=TA_CENTER, leading=34))],
             [Paragraph(s['label'], ParagraphStyle('sl', fontName=FONT_BOLD, fontSize=7.5,
                                                   textColor=s['color'], alignment=TA_CENTER, leading=10))]],
            colWidths=[CONTENT_W / 5 - 4*mm]
        )
        inner.setStyle(TableStyle([
            ('ALIGN',  (0,0),(-1,-1),'CENTER'),
            ('VALIGN', (0,0),(-1,-1),'MIDDLE'),
            ('BOTTOMPADDING',(0,0),(-1,-1), 10),
            ('TOPPADDING',   (0,0),(-1,-1), 10),
        ]))
        cells.append(inner)

    dash = Table([cells], colWidths=[CONTENT_W / 5] * 5)
    cell_style = [
        ('ALIGN',  (0,0),(-1,-1),'CENTER'),
        ('VALIGN', (0,0),(-1,-1),'MIDDLE'),
        ('GRID',   (0,0),(-1,-1), 1, C_WHITE),
        ('LEFTPADDING', (0,0),(-1,-1), 0),
        ('RIGHTPADDING', (0,0),(-1,-1), 0),
    ]
    for i, sev in enumerate(SEV_ORDER):
        cell_style.append(('BACKGROUND', (i,0),(i,0), SEV[sev]['bg']))
        # Add a thick bottom border for the accent
        cell_style.append(('LINEBELOW', (i,0),(i,0), 3, SEV[sev]['color']))
    
    dash.setStyle(TableStyle(cell_style))
    story.append(dash)
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(f"Total identificados: <b>{total} hallazgos</b>", styles['caption']))
    story.append(Spacer(1, 8*mm))

    story.append(Paragraph("Distribución por Severidad", styles['subsect']))
    max_c = max(fc.values()) if fc else 1
    for sev in SEV_ORDER:
        story.append(SeverityBar(sev, fc.get(sev, 0), max_c, CONTENT_W))
        story.append(Spacer(1, 2*mm))
    story.append(Spacer(1, 6*mm))

    story.append(Paragraph("Matriz de Riesgo - Probabilidad x Impacto", styles['subsect']))
    story.append(Paragraph('<font color="#A0A0A0">Probabilidad abajo / Impacto derecha</font>', styles['caption']))
    story.append(Spacer(1, 2*mm))

    def mc(lbl, bg, col):
        return Paragraph(f'<b>{lbl}</b>',
                         ParagraphStyle('mc', fontName=FONT_SEMI, fontSize=8,
                                        backColor=bg, textColor=col,
                                        alignment=TA_CENTER, leading=11))

    RD, DO = HexColor('#C62828'), HexColor('#D84315')
    YL, BL = HexColor('#F57F17'), HexColor('#1565C0')
    RBG, OBG = HexColor('#FFCDD2'), HexColor('#FFE0B2')
    YBG, BBG = HexColor('#FFFDE7'), HexColor('#E3F2FD')

    mat = [
        ["", Paragraph('<b>Bajo</b>',    styles['table_hdr']),
             Paragraph('<b>Medio</b>',   styles['table_hdr']),
             Paragraph('<b>Alto</b>',    styles['table_hdr']),
             Paragraph('<b>Crítico</b>', styles['table_hdr'])],
        [Paragraph('<b>Alta</b>',  styles['table_cell']), mc("Medio",YBG,YL), mc("Alto",OBG,DO), mc("Crítico",RBG,RD), mc("Crítico",RBG,RD)],
        [Paragraph('<b>Media</b>', styles['table_cell']), mc("Bajo",BBG,BL),  mc("Medio",YBG,YL),mc("Alto",OBG,DO),    mc("Crítico",RBG,RD)],
        [Paragraph('<b>Baja</b>',  styles['table_cell']), mc("Bajo",BBG,BL),  mc("Bajo",BBG,BL), mc("Medio",YBG,YL),  mc("Alto",OBG,DO)],
    ]
    cw = (CONTENT_W - 22*mm) / 4
    mat_t = mk_table(mat, [22*mm, cw, cw, cw, cw],
                     [('BACKGROUND', (0,0),(-1,0), C_PRIMARY),
                      ('TEXTCOLOR',  (0,0),(-1,0), C_WHITE),
                      ('BACKGROUND', (0,0),(0,-1), HexColor('#F0EEFF')),
                      ('ALIGN',      (0,0),(-1,-1),'CENTER'),
                      ('FONTNAME',   (0,0),(0,-1), FONT_SEMI),
                      ('FONTSIZE',   (0,0),(0,-1), 8),
                      ('TOPPADDING',   (0,0),(-1,-1), 9),
                      ('BOTTOMPADDING',(0,0),(-1,-1), 9)])
    story.append(mat_t)
    return story


def build_severity_scale(data, styles):
    story = section_header("04 - Metodología de Severidad CVSS", styles)
    story.append(Paragraph(
        "Clasificación de severidad basada en puntuación CVSS v3.1 y criterios de impacto.",
        styles['body']
    ))
    story.append(Spacer(1, 4*mm))

    sev_rows = [[Paragraph("NIVEL", styles['table_hdr']),
                 Paragraph("CVSS v3.1", styles['table_hdr']),
                 Paragraph("DESCRIPCIÓN", styles['table_hdr']),
                 Paragraph("ACCIÓN", styles['table_hdr'])]]
    sev_data = [
        ("critico", "9.0 - 10.0", "Explotación trivial con impacto total.",                          "Remediar < 24h"),
        ("alto",    "7.0 - 8.9",  "Alta probabilidad de explotación. Impacto significativo.",        "Remediar < 1 semana"),
        ("medio",   "4.0 - 6.9",  "Explotación posible. Impacto moderado.",                          "Remediar < 1 mes"),
        ("bajo",    "0.1 - 3.9",  "Explotación difícil o impacto menor.",                          "Remediar en roadmap"),
        ("info",    "0.0",        "Hallazgo informativo. Aporta contexto.",                          "Documentar"),
    ]
    for sev_key, cvss_range, desc, action in sev_data:
        s = SEV[sev_key]
        color_hex = s['color'].hexval()[2:]
        sev_rows.append([
            Paragraph(f'<font color="#{color_hex}"><b>{s["label"]}</b></font>', styles['table_cell']),
            Paragraph(cvss_range, styles['table_cell']),
            Paragraph(desc, styles['table_cell']),
            Paragraph(action, styles['table_cell']),
        ])
    story.append(mk_table(sev_rows,
                          [22*mm, 22*mm, CONTENT_W - 22*mm - 22*mm - 38*mm, 38*mm],
                          [('BACKGROUND', (0,0),(-1,0), C_PRIMARY),
                           ('TEXTCOLOR',  (0,0),(-1,0), C_WHITE),
                           ('ROWBACKGROUNDS', (0,1),(-1,-1), [C_WHITE, HexColor('#F7F5FF')])]))
    return story


def build_scope(data, styles):
    story = section_header("05 - Alcance y Activos Evaluados", styles)

    info = [
        [Paragraph('<b>Tipo de evaluación</b>', styles['table_cell']),  Paragraph(data['engagement_type'], styles['table_cell'])],
        [Paragraph('<b>Metodología</b>',        styles['table_cell']),  Paragraph(data['methodology'],     styles['table_cell'])],
        [Paragraph('<b>Período</b>',            styles['table_cell']),  Paragraph(f"{data['start_date']} -> {data['end_date']}", styles['table_cell'])],
        [Paragraph('<b>Versión</b>',            styles['table_cell']),  Paragraph(data['version'],         styles['table_cell'])],
    ]
    story.append(mk_table(info, [45*mm, CONTENT_W - 45*mm],
                          [('BACKGROUND', (0,0),(0,-1), HexColor('#F0EEFF'))]))
    story.append(Spacer(1, 5*mm))

    story.append(Paragraph("Sistemas Evaluados", styles['subsect']))
    hdr  = [[Paragraph("SISTEMA", styles['table_hdr']), Paragraph("DESCRIPCIÓN", styles['table_hdr']), Paragraph("MODALIDAD", styles['table_hdr'])]]
    rows = hdr + [[Paragraph(f'<b>{sys}</b>', styles['table_cell']), Paragraph(desc, styles['table_cell']), Paragraph(mod, styles['table_cell'])]
                  for sys, desc, mod in data["systems_tested"]]
    story.append(mk_table(rows, [58*mm, CONTENT_W - 58*mm - 28*mm, 28*mm],
                          [('BACKGROUND', (0,0),(-1,0), C_PRIMARY),
                           ('TEXTCOLOR',  (0,0),(-1,0), C_WHITE),
                           ('ROWBACKGROUNDS',(0,1),(-1,-1),[C_WHITE, HexColor('#F7F5FF')])]))

    story.append(Spacer(1, 5*mm))
    story.append(Paragraph("Fuera del Alcance", styles['subsect']))
    for item in data["out_of_scope"]:
        story.append(Paragraph(f'<font color="#C62828">-</font>  {item}', styles['bullet']))
    return story


def build_strengths(data, styles):
    items = data.get("strengths", [])
    if not items: return []
    # No section number for strengths if we want it to be part of summary or a minor section
    # Let's make it its own minor section 05.1 or just part of 01
    story = [Paragraph("Fortalezas de Seguridad Identificadas", styles['subsect'])]
    for i, item in enumerate(items, 1):
        row = [[Paragraph(f'<font color="#6E40C9"><b>{i:02d}</b></font>', styles['table_cell']),
                Paragraph(item["description"], styles['body'])]]
        story.append(mk_table(row, [10*mm, CONTENT_W - 10*mm], [('BACKGROUND', (0,0),(0,0), HexColor('#F0EEFF'))]))
        if item.get("evidence"):
            story.append(Paragraph(f'<font color="#A0A0A0">Evidencia:</font> {item["evidence"]}', styles['caption']))
        story.append(Spacer(1, 2*mm))
    return story


def build_attack_narrative(data, styles):
    story = section_header("02 - Cadena de Ataque y Línea de Tiempo", styles)
    story.append(Paragraph("Fases ejecutadas durante la evaluación para compromiso de los objetivos.", styles['body']))
    story.append(Spacer(1, 5*mm))

    for i, (phase, duration, desc) in enumerate(data["attack_narrative"], 1):
        ph_key = PHASE_ORDER[i - 1] if i-1 < len(PHASE_ORDER) else "surface_expansion"
        ph     = PHASE[ph_key]
        rows = [[Paragraph(f'<font color="#FFFFFF"><b>{phase}</b></font>', styles['table_hdr']),
                 Paragraph(f'<font color="#FFFFFF">{duration}</font>', styles['table_cell'])]]
        story.append(mk_table(rows, [CONTENT_W * 0.75, CONTENT_W * 0.25], [('BACKGROUND', (0,0),(-1,-1), ph['color'])]))
        story.append(mk_table([[Paragraph(desc, styles['body'])]], [CONTENT_W], [('BACKGROUND', (0,0),(-1,-1), HexColor('#F8F8FC'))]))
        story.append(Spacer(1, 4*mm))
    return story


def build_findings(data, styles):
    all_f = data.get("findings", [])
    if not all_f: return []

    story = section_header("06 - Hallazgos Técnicos Detallados", styles)
    story.append(Paragraph("A continuación se presenta el resumen maestro de todos los hallazgos identificados, seguido del análisis técnico profundo de cada uno.", styles['body']))
    story.append(Spacer(1, 4*mm))
    
    # 06-A: Summary Table Listing all Findings
    story.append(Paragraph("Resumen de Hallazgos", styles['subsect']))
    hdr  = [[Paragraph("ID", styles['table_hdr']), Paragraph("HALLAZGO", styles['table_hdr']), Paragraph("SEV.", styles['table_hdr']), Paragraph("CVSS", styles['table_hdr']), Paragraph("ESTADO", styles['table_hdr'])]]
    
    # Sort for the summary table: Critical -> Info
    ORDER = ["critico", "alto", "medio", "bajo", "info"]
    sorted_all = []
    for s_k in ORDER:
        sorted_all.extend([f for f in all_f if f["severity"] == s_k])

    rows = hdr + [[Paragraph(f["id"], styles['table_cell']),
                   Paragraph(f["title"], styles['table_cell']),
                   Paragraph(SEV.get(f["severity"], SEV["info"])["label"], styles['table_cell']),
                   Paragraph(str(f.get("cvss_score", "N/A")), styles['table_cell']),
                   Paragraph(f.get("status", "Validated"), styles['table_cell'])]
                  for f in sorted_all]
                  
    story.append(mk_table(rows, [20*mm, CONTENT_W - 85*mm, 22*mm, 18*mm, 25*mm],
                          [('BACKGROUND', (0,0),(-1,0), C_PRIMARY),
                           ('TEXTCOLOR',  (0,0),(-1,0), C_WHITE),
                           ('ROWBACKGROUNDS', (0,1),(-1,-1), [C_WHITE, HexColor('#F8F9FA')])]))
    
    story.append(PageBreak())
    
    for s_key in ORDER:
        s_findings = [f for f in all_f if f["severity"] == s_key]
        if not s_findings: continue
        
        s_info = SEV[s_key]
        
        # Severity Group Banner
        banner_data = [[Paragraph(f"SEVERIDAD: {s_info['label'].upper()}", 
                         ParagraphStyle('svn', fontName=FONT_BOLD, fontSize=11, textColor=C_WHITE))]]
        banner = Table(banner_data, colWidths=[CONTENT_W])
        banner.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,-1), s_info['color']),
            ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0),(-1,-1), 15),
            ('TOPPADDING', (0,0),(-1,-1), 8),
            ('BOTTOMPADDING', (0,0),(-1,-1), 8),
        ]))
        story.append(banner)
        story.append(Spacer(1, 8*mm))
        
        for f in s_findings:
            story.extend(build_finding_block(f, styles))
            story.append(Spacer(1, 6*mm))
            story.append(DividerLine(CONTENT_W, HexColor('#DDDDEE'), 0.4))
            story.append(Spacer(1, 10*mm))
        
        story.append(PageBreak())
        
    return story


def build_finding_block(f, styles):
    story = []
    # 1. Card Header
    story.append(FindingHeader(
        f.get("id", "N/A"), 
        f.get("title", "Untitled"), 
        f.get("severity", "info"), 
        CONTENT_W, 
        phase=f.get("phase"), 
        confidence=f.get("confidence")
    ))
    story.append(Spacer(1, 4*mm))

    # 2. Metadata "Borderless" Table
    s = SEV.get(f.get("severity", "info"), SEV["info"])
    def lbl(txt): return Paragraph(f'<b>{txt}</b>', ParagraphStyle('lbl', fontName=FONT_SEMI, fontSize=8.5, textColor=C_TEXT_MUTED))
    def val(txt): return Paragraph(str(txt), styles['table_cell'])
    
    # Format CVSS Vector as Code Block
    vector_style = ParagraphStyle('vector', fontName='Courier', fontSize=7.5, textColor=C_PRIMARY, 
                                 backColor=C_CVSS_BG, borderRadius=3, borderPadding=3)
    cvss_v = Paragraph(f.get("cvss_vector", "N/A"), vector_style)

    # Format Límite as Bullets if long
    limite_txt = f.get('validation_limit', 'Verificación estándar')
    if len(limite_txt) > 50:
        pts = limite_txt.split('. ')
        limite_val = '<br/>'.join([f'• {p.strip()}' for p in pts if p.strip()])
    else:
        limite_val = limite_txt

    meta_rows = [
        [lbl('Severidad'), Paragraph(f"<b>{s['label']}</b>", styles['table_cell']), lbl('CVSS v3.1'), Paragraph(f"<b>{f.get('cvss_score', 'N/A')}</b>", styles['table_cell'])],
        [lbl('Sistema'),   val(f.get('system', 'N/A')), lbl('Estado'),   Paragraph(f"✔ {f.get('status', 'Validated')}", styles['table_cell'])],
        [lbl('Vector'),     cvss_v,        lbl('Límite'),   Paragraph(limite_val, styles['table_cell'])],
    ]
    
    # Use mk_table but with transparent grid
    col = CONTENT_W / 4
    story.append(mk_table(meta_rows, [col*0.6, col*1.4, col*0.6, col*1.4], [
        ('GRID', (0,0),(-1,-1), 0, C_BG_PAGE),
        ('LINEBELOW', (0,0),(-1,-1), 0.5, C_LINE),
        ('VALIGN', (0,0),(-1,-1), 'TOP'),
        ('LEFTPADDING', (0,0),(-1,-1), 12),
        ('BOTTOMPADDING', (0,0),(-1,-1), 10),
    ]))
    story.append(Spacer(1, 4*mm))

    # 3. Verified Section (Separate Card)
    v_body = f.get('verified', 'No se proporcionaron detalles de verificación.')
    e_body = f.get('evidence', 'No se adjuntó evidencia específica.')
    
    v_story = [
        Paragraph("¿Qué se verificó?", styles['subsect']),
        Paragraph(v_body, ParagraphStyle('bp', fontName=FONT_REG, fontSize=10, textColor=C_DARK_BG, leading=16, alignment=TA_JUSTIFY)),
        Spacer(1, 4*mm),
        Paragraph("Evidencia para reproducción", styles['subsect']),
        mk_table([[Paragraph(e_body.replace('<','&lt;').replace('>','&gt;'), styles['code_p'])]], [CONTENT_W - 20*mm], [('BACKGROUND', (0,0),(-1,-1), C_DARK_BG2)])
    ]
    
    # Wrap verification in a Card-like table
    story.append(mk_table([[v_story]], [CONTENT_W], [
        ('BACKGROUND', (0,0),(-1,-1), C_CARD_BG),
        ('BOX', (0,0),(-1,-1), 0.5, C_LINE),
        ('TOPPADDING', (0,0),(-1,-1), 12),
        ('LEFTPADDING', (0,0),(-1,-1), 12),
        ('RIGHTPADDING', (0,0),(-1,-1), 12),
        ('BOTTOMPADDING', (0,0),(-1,-1), 12),
    ]))
    story.append(Spacer(1, 6*mm))

    # Evidence images Logic...
    ev_folder_name = f.get("evidence_folder") or f.get("id")
    if ev_folder_name:
        ev_dir = os.path.join(EVIDENCIA_DIR, ev_folder_name)
        if os.path.isdir(ev_dir):
            # Same logic as before but wrapped in Card
            images_story = [Paragraph("Capturas de Pantalla", styles['subsect'])]
            try:
                img_files = sorted([fn for fn in os.listdir(ev_dir) if os.path.splitext(fn.lower())[1] in {'.png', '.jpg', '.jpeg'}])
                for fn in img_files:
                    img_path = os.path.join(ev_dir, fn)
                    try:
                        with PILImage.open(img_path) as pil_img:
                            orig_w, orig_h = pil_img.size
                        max_w = CONTENT_W - 40*mm
                        draw_w = min(orig_w, max_w)
                        draw_h = orig_h * (draw_w / orig_w)
                        images_story.append(Image(img_path, width=draw_w, height=draw_h))
                        images_story.append(Paragraph(fn, styles['caption']))
                        images_story.append(Spacer(1, 4*mm))
                    except Exception: pass
                
                if len(images_story) > 1:
                    story.append(mk_table([[images_story]], [CONTENT_W], [
                        ('BACKGROUND', (0,0),(-1,-1), C_CARD_BG),
                        ('BOX', (0,0),(-1,-1), 0.5, C_LINE),
                        ('LEFTPADDING', (0,0),(-1,-1), 12),
                        ('TOPPADDING', (0,0),(-1,-1), 12),
                    ]))
                    story.append(Spacer(1, 6*mm))
            except Exception: pass

    # 4. Impact & Remediation
    imp_v = f.get('impact_verified', 'Impacto técnico confirmado en los activos evaluados.')
    imp_p = f.get('impact_potential', 'Riesgo de escalamiento o exposición de datos adicionales.')
    
    impact = [[lbl('Hecho verificado'), Paragraph(imp_v, styles['table_cell'])],
              [lbl('Riesgo potencial'), Paragraph(imp_p, styles['table_cell'])]]
    
    f_rem = f.get("remediation", [])
    if not isinstance(f_rem, list): f_rem = []
    
    rem_rows = [[Paragraph("ACCION", styles['table_hdr']), Paragraph("DETALLE", styles['table_hdr']), Paragraph("RESPONSABLE", styles['table_hdr']), Paragraph("PLAZO", styles['table_hdr'])]]
    for r in f_rem:
        if len(r) == 4:
            rem_rows.append([Paragraph(str(r[0]), styles['table_cell']), 
                             Paragraph(str(r[1]), styles['table_cell']), 
                             Paragraph(str(r[2]), styles['table_cell']), 
                             Paragraph(str(r[3]), styles['table_cell'])])
    
    inner_w = CONTENT_W - 10*mm
    final_card = [
        Paragraph("Impacto", styles['subsect']),
        mk_table(impact, [40*mm, inner_w - 40*mm], [('GRID', (0,0),(-1,-1), 0, C_WHITE), ('LINEBELOW', (0,0),(-1,-1), 0.5, C_LINE)]),
        Spacer(1, 4*mm),
        Paragraph("Plan de Remediación", styles['subsect']),
        mk_table(rem_rows, [28*mm, inner_w - 28*mm - 35*mm - 22*mm, 35*mm, 22*mm], [('BACKGROUND', (0,0),(-1,0), HexColor('#1A3A1A')), ('TEXTCOLOR', (0,0),(-1,0), C_WHITE)])
    ]
    
    story.append(mk_table([[final_card]], [CONTENT_W], [
        ('BACKGROUND', (0,0),(-1,-1), C_CARD_BG),
        ('BOX', (0,0),(-1,-1), 0.5, C_LINE),
        ('TOPPADDING', (0,0),(-1,-1), 12),
        ('LEFTPADDING', (0,0),(-1,-1), 12),
        ('RIGHTPADDING', (0,0),(-1,-1), 12),
        ('BOTTOMPADDING', (0,0),(-1,-1), 12),
    ]))

    # We only wrap the header and metadata table together to prevent orphans, 
    # but let the rest of the finding (evidence/images) split across pages.
    if len(story) >= 3:
        return [KeepTogether(story[:3])] + story[3:]
    return story


def build_remediation(data, styles):
    story = section_header("07 - Plan de Remediación Maestro (Hoja de Ruta)", styles)
    story.append(Paragraph("Esta tabla consolidada permite a los responsables de área priorizar las correcciones basándose en el nivel de riesgo y el esfuerzo sugerido.", styles['body']))
    story.append(Spacer(1, 6*mm))

    hdr = [[Paragraph("PRIO", styles['table_hdr']), 
            Paragraph("ID", styles['table_hdr']), 
            Paragraph("HALLAZGO", styles['table_hdr']), 
            Paragraph("RESPONSABLE", styles['table_hdr']), 
            Paragraph("PLAZO", styles['table_hdr']), 
            Paragraph("ESTADO", styles['table_hdr'])]]
            
    all_f = data.get("findings", [])
    # Sorted by SEV
    ORDER = ["critico", "alto", "medio", "bajo", "info"]
    master_rows = hdr
    for s_k in ORDER:
        for f in all_f:
            if f["severity"] == s_k:
                # Get the first remediation action as "main action" or the title
                action = f.get("remediation", [])
                resp = action[0][2] if action and len(action[0]) >= 3 else "TBD"
                pz = action[0][3] if action and len(action[0]) >= 4 else "TBD"
                
                master_rows.append([
                    Paragraph(f"<b>{s_k.upper()}</b>", ParagraphStyle('p', fontName=FONT_BOLD, fontSize=7, textColor=SEV[s_k]['color'])),
                    Paragraph(f["id"], styles['table_cell']),
                    Paragraph(f["title"], styles['table_cell']),
                    Paragraph(resp, styles['table_cell']),
                    Paragraph(pz, styles['table_cell']),
                    Paragraph("Pendiente", styles['table_cell'])
                ])
                
    story.append(mk_table(master_rows, [22*mm, 20*mm, CONTENT_W - 105*mm, 26*mm, 17*mm, 20*mm],
                          [('BACKGROUND', (0,0),(-1,0), C_PRIMARY),
                           ('TEXTCOLOR',  (0,0),(-1,0), C_WHITE),
                           ('ROWBACKGROUNDS', (0,1),(-1,-1), [C_WHITE, HexColor('#F8FAFF')])]))
    return story


def build_strategic(data, styles):
    story = section_header("08 - Recomendaciones Estratégicas y Gaps de Detección", styles)
    story.append(Paragraph("Más allá de las vulnerabilidades técnicas, se identificaron áreas de oportunidad en la arquitectura y controles compensatorios.", styles['body']))
    story.append(Spacer(1, 5*mm))

    # Merge Opportunities + Gaps
    story.append(Paragraph("Gaps de Visibilidad y Monitoreo", styles['subsect']))
    for gap in data.get("detection_gaps", []):
        story.append(Paragraph(f"<b>Área: {gap['area']}</b>", styles['body']))
        for item in gap["gaps"]:
            story.append(Paragraph(f'<font color="#D84315">!</font>  {item}', styles['bullet']))
    
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph("Recomendaciones de Arquitectura y Gobernanza", styles['subsect']))
    for item in data.get("strategic_opportunities", []):
        story.append(Paragraph(f'<font color="#1565C0">»</font>  {item["description"]}', styles['bullet']))
    
    return story


def build_iocs(data, styles):
    story = section_header("09 - Indicadores de Compromiso (IoC)", styles)
    for ioc in data["iocs"]:
        rows = [[Paragraph(ioc["vector"], styles['ioc_title'])],
                [Paragraph('<b>Qué buscar</b>', styles['table_cell']), Paragraph(ioc['what'], styles['body'])],
                [Paragraph('<b>Dónde buscarlo</b>', styles['table_cell']), Paragraph(ioc['where'], styles['body'])]]
        story.append(mk_table(rows, [38*mm, CONTENT_W - 38*mm], [('SPAN', (0,0),(-1,0)), ('BACKGROUND', (0,0),(-1,0), C_DARK_BG2)]))
        story.append(Spacer(1, 4*mm))
    return story


def build_disclaimer(data, styles):
    text = data.get("disclaimer") or "Este documento es confidencial y ha sido elaborado para uso exclusivo del cliente."
    story = section_header("10 - Descargo de Responsabilidad", styles)
    story.append(Paragraph(text, styles['body']))
    return story


def build_appendix(data, styles):
    story = section_header("11 - Apéndice Técnico", styles)
    story.append(Paragraph("Control de Versiones", styles['subsect']))
    vc = [[Paragraph("VERSIÓN",  styles['table_hdr']), Paragraph("FECHA", styles['table_hdr']), Paragraph("CAMBIO", styles['table_hdr'])]] + \
         [[Paragraph(data['version'], styles['table_cell']), Paragraph(data['report_date'], styles['table_cell']), Paragraph("Versión Final", styles['table_cell'])]]
    story.append(mk_table(vc, [25*mm, 28*mm, CONTENT_W - 53*mm], [('BACKGROUND', (0,0),(-1,0), C_PRIMARY)]))
    story.append(Spacer(1, 10*mm))
    story.append(Paragraph(f"<b>{data['auditor_name']}</b> · {data['auditor_role']} · {data['company']}", styles['sig']))
    return story


def generate_report(data, output_path):
    print(f"[+] Generando PDF: {output_path}")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    styles = build_styles()

    cover_frame = Frame(0, 0, W, H, leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0, id='cf')
    cover_tpl   = PageTemplate(id='Cover', frames=[cover_frame], pagesize=A4)

    normal_frame = Frame(MARGIN_L, MARGIN_B + 10*mm, CONTENT_W, H - MARGIN_T - MARGIN_B - 20*mm, 
                         leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0, id='nf')
    normal_tpl   = PageTemplate(id='Normal', frames=[normal_frame], pagesize=A4)

    story = []
    story.extend(build_cover(data, LOGO_PATH, styles))
    story.append(NextPageTemplate('Normal'))
    story.append(PageBreak())
    
    for section in [
        build_cover_letter,    # 00
        build_doc_details,
        build_toc,
        build_exec_summary,     # 01
        build_dashboard,        # 02
        build_attack_narrative, # 03
        build_severity_scale,   # 04
        build_scope,            # 05
        build_findings,         # 06
        build_remediation,      # 07
        build_strategic,        # 08
        build_iocs,             # 09
        build_disclaimer,       # 10
        build_appendix          # 11
    ]:
        content = section(data, styles)
        if content:
            story.extend(content)
            if section != build_appendix:
                story.append(PageBreak())
    
    doc = ReportDocTemplate(output_path, pagesize=A4, pageTemplates=[cover_tpl, normal_tpl])
    doc.multiBuild(story, canvasmaker=lambda f, **kw: ReportCanvas(f, data, LOGO_PATH, **kw))
    print(f"[OK] PDF listo: {output_path}")


def load_from_yaml(yaml_path):
    if not _HAS_YAML: return None
    if not os.path.exists(yaml_path): return None
    with open(yaml_path, 'r', encoding='utf-8') as f:
        raw = yaml.safe_load(f)
    
    meta = raw.get('meta', {})
    data = {
        'client_name':      meta.get('client_name', '[CLIENTE]'),
        'client_industry':  meta.get('client_industry', ''),
        'target_scope':     meta.get('target_scope', ''),
        'engagement_type':  meta.get('engagement_type', ''),
        'methodology':      meta.get('methodology', ''),
        'start_date':       meta.get('start_date', ''),
        'end_date':         meta.get('end_date', ''),
        'report_date':      meta.get('report_date', datetime.now().strftime("%Y-%m-%d")),
        'version':          meta.get('version', '1.0'),
        'auditor_name':     meta.get('auditor_name', 'Devetac Maximiliano'),
        'auditor_role':     meta.get('auditor_role', 'Principal Security Consultant'),
        'company':          meta.get('company', 'Devetac'),
        'company_website':  meta.get('company_website', ''),
        'findings_count':   raw.get('findings_count', {}),
        'executive_narrative': raw.get('executive_narrative', ''),
        'executive_metrics':   raw.get('executive_metrics', []),
        'attacker_can_do':     raw.get('attacker_can_do', []),
        'immediate_actions':   [tuple(x) for x in raw.get('immediate_actions', [])],
        'legal_exposure':      [tuple(x) for x in raw.get('legal_exposure', [])],
        'attack_narrative':    [tuple(x) for x in raw.get('attack_narrative', [])],
        'detection_gaps':      raw.get('detection_gaps', []),
        'defensive_gaps':      [tuple(x) for x in raw.get('defensive_gaps', [])],
        'findings':            [],
        'remediation_plan':    raw.get('remediation_plan', {}),
        'iocs':                raw.get('iocs', []),
        'tools_used':          [tuple(x) for x in raw.get('tools_used', [])],
        'systems_tested':      [tuple(x) for x in raw.get('systems_tested', [])],
        'out_of_scope':        raw.get('out_of_scope', []),
        'strengths':           raw.get('strengths', []),
        'strategic_opportunities': raw.get('strategic_opportunities', []),
    }
    
    for f in raw.get('findings', []):
        finding = dict(f)
        if 'remediation' in finding:
            finding['remediation'] = [tuple(r) for r in finding['remediation']]
        data['findings'].append(finding)
        
    return data


# Nota: acá terminaba el `if __name__ == "__main__":` original (leía
# 04_hallazgos/findings.yaml con paths hardcodeados y sincronizaba carpetas de
# evidencia con imágenes). glaive no lo necesita — invoca `generate_report(data,
# output_path)` directo desde `glaive/pdf/mapper.py`, con el dict ya armado
# desde el Store. `load_from_yaml` queda arriba sin usar (inofensivo, por si
# alguna vez hace falta cargar un YAML con este mismo formato).

