from io import BytesIO
from xhtml2pdf import pisa

def html_to_pdf(source_html):
    pdf = BytesIO()
    pisa_status = pisa.CreatePDF(source_html, dest=pdf)
    if pisa_status.err:
        return None
    pdf.seek(0)
    return pdf
