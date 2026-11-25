"""Render the same report sections as a printable PDF and an editable Word file."""
from io import BytesIO
import json
import subprocess
from pathlib import Path
import re

from docx import Document
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

INK = "#172A40"
MUTED = "#485C70"
RULE = "#D9D9D9"
STRIPE = "#F1F5F8"
WIDTHS = {
    2: (0.29, 0.71),
    3: (0.23, 0.51, 0.26),
    4: (0.17, 0.23, 0.34, 0.26),
    5: (0.10, 0.36, 0.16, 0.12, 0.26),
}
PDF_TYPE = "application/pdf"
WORD_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def column_widths(columns):
    if columns[0] == "Técnica" and len(columns) == 5:
        return (0.15, 0.12, 0.21, 0.14, 0.38)
    if columns[0] == "Técnica":
        return (0.56, 0.18, 0.26)
    return WIDTHS[len(columns)]


def clean(value):
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff\ufffe\uffff]", "", str(value))


def render_pdf(report):
    renderer = Path(__file__).with_name("report_renderer") / "render.mjs"
    result = subprocess.run(["node", str(renderer)], input=json.dumps(report).encode(),
                            stdout=subprocess.PIPE, check=True, timeout=90)
    return result.stdout


def word_property(parent, name, value):
    element = OxmlElement("w:" + name)
    element.set(qn("w:val"), value)
    parent.append(element)
    return element


def render_docx(report):
    doc = Document()
    doc.core_properties.title = report["title"]
    doc.core_properties.author = "TacticLens"
    page = doc.sections[0]
    page.page_width, page.page_height = Inches(8.5), Inches(11)
    page.left_margin = page.right_margin = Inches(0.7)
    page.top_margin, page.bottom_margin = Inches(0.78), Inches(0.7)
    normal = doc.styles["Normal"]
    normal.font.name, normal.font.size = "Calibri", Pt(11)
    normal.paragraph_format.space_after = Pt(7)
    for name in ("Title", "Heading 1"):
        doc.styles[name].font.color.rgb = RGBColor(0, 0, 0)

    page.header.paragraphs[0].text = "TacticLens  /  Observatorio Cowrie"
    footer = page.footer.paragraphs[0]
    footer.add_run(f'{report["reference"]}   |   Página ')
    number = OxmlElement("w:fldSimple")
    number.set(qn("w:instr"), "PAGE")
    footer._p.append(number)

    def grid(columns, rows):
        table = doc.add_table(rows=0, cols=len(columns))
        table.style = "Table Grid"
        table.autofit = False
        widths = [Inches(7.1 * fraction) for fraction in column_widths(columns)]
        for col, width in zip(table.columns, widths):
            col.width = width
        borders = OxmlElement("w:tblBorders")
        for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
            node = word_property(borders, side, "single")
            node.set(qn("w:sz"), "4")
            node.set(qn("w:color"), RULE[1:])
        table._tbl.tblPr.append(borders)
        for index, values in enumerate([columns, *rows]):
            row = table.add_row()
            props = row._tr.get_or_add_trPr()
            word_property(props, "cantSplit", "true")
            if index == 0:
                word_property(props, "tblHeader", "true")
            for cell, width, value in zip(row.cells, widths, values):
                cell.width = width
                fill = OxmlElement("w:shd")
                fill.set(qn("w:fill"), (INK if index == 0 else STRIPE if index % 2 == 0 else "#FFFFFF")[1:])
                cell._tc.get_or_add_tcPr().append(fill)
                p = cell.paragraphs[0]
                p.paragraph_format.space_before = p.paragraph_format.space_after = Pt(4)
                run = p.add_run(clean(value))
                run.font.size = Pt(9)
                if index == 0:
                    run.bold = True
                    run.font.color.rgb = RGBColor(255, 255, 255)

    title = doc.add_paragraph(report["title"], style="Title")
    border = OxmlElement("w:pBdr")
    word_property(border, "bottom", "nil")
    title._p.get_or_add_pPr().append(border)
    doc.add_paragraph(report["status"])
    grid(("Campo", "Registro"), report["metadata"])
    for section in report["sections"]:
        doc.add_heading(section["title"], level=1)
        for index, paragraph in enumerate(section["paragraphs"]):
            note = doc.add_paragraph(clean(paragraph))
            if section["rows"] and index == len(section["paragraphs"]) - 1:
                note.paragraph_format.keep_with_next = True
        if section["rows"]:
            grid(section["columns"], section["rows"])
    stream = BytesIO()
    doc.save(stream)
    return stream.getvalue()
