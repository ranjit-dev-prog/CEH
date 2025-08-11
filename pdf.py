import os
from PyPDF2 import PdfReader, PdfWriter
import pikepdf
from pdf2image import convert_from_path
from PIL import Image
import pandas as pd
from docx2pdf import convert as docx2pdf_convert
from fpdf import FPDF


def clean_path(path):
    # User input se aane wale path ke extra quotes hata de
    return path.strip().strip('"').strip("'")


def show_pdf_metadata(pdf_path):
    pdf_path = clean_path(pdf_path)
    try:
        pdf = pikepdf.open(pdf_path)
        metadata = pdf.docinfo
        print("\nPDF Metadata:")
        if metadata:
            for k, v in metadata.items():
                print(f"{k}: {v}")
        else:
            print("No metadata found.")
        pdf.close()
    except Exception as e:
        print(f"Error reading metadata: {e}")


def split_pdf(pdf_path, start_page, end_page, output_path):
    pdf_path = clean_path(pdf_path)
    output_path = clean_path(output_path)
    try:
        reader = PdfReader(pdf_path)
        writer = PdfWriter()
        total_pages = len(reader.pages)
        if start_page < 1 or end_page > total_pages or start_page > end_page:
            print(f"Invalid page range! PDF has {total_pages} pages.")
            return
        for i in range(start_page - 1, end_page):
            writer.add_page(reader.pages[i])
        with open(output_path, "wb") as f:
            writer.write(f)
        print(f"Split PDF saved to: {output_path}")
    except Exception as e:
        print(f"Error splitting PDF: {e}")


def merge_pdfs(pdf_paths, output_path):
    pdf_paths = [clean_path(p) for p in pdf_paths]
    output_path = clean_path(output_path)
    try:
        writer = PdfWriter()
        for pdf_file in pdf_paths:
            reader = PdfReader(pdf_file)
            for page in reader.pages:
                writer.add_page(page)
        with open(output_path, "wb") as f:
            writer.write(f)
        print(f"Merged PDF saved to: {output_path}")
    except Exception as e:
        print(f"Error merging PDFs: {e}")


def pdf_to_images(pdf_path, output_folder):
    pdf_path = clean_path(pdf_path)
    output_folder = clean_path(output_folder)
    try:
        pages = convert_from_path(pdf_path)
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        for i, page in enumerate(pages):
            image_path = os.path.join(output_folder, f"page_{i+1}.png")
            page.save(image_path, "PNG")
            print(f"Saved image: {image_path}")
    except Exception as e:
        print(f"Error converting PDF to images: {e}")


def images_to_pdf(image_paths, output_pdf):
    image_paths = [clean_path(p) for p in image_paths]
    output_pdf = clean_path(output_pdf)
    try:
        images = [Image.open(img).convert("RGB") for img in image_paths]
        images[0].save(output_pdf, save_all=True, append_images=images[1:])
        print(f"Images merged into PDF: {output_pdf}")
    except Exception as e:
        print(f"Error converting images to PDF: {e}")


def pdf_to_text(pdf_path, output_txt):
    pdf_path = clean_path(pdf_path)
    output_txt = clean_path(output_txt)
    try:
        reader = PdfReader(pdf_path)
        full_text = []
        for page in reader.pages:
            text = page.extract_text()
            if text:
                full_text.append(text)
        if full_text:
            with open(output_txt, "w", encoding="utf-8") as f:
                f.write("\n\n".join(full_text))
            print(f"PDF text extracted to: {output_txt}")
        else:
            print("No text extracted from PDF.")
    except Exception as e:
        print(f"Error extracting text: {e}")


def text_to_pdf(text_path, output_pdf):
    text_path = clean_path(text_path)
    output_pdf = clean_path(output_pdf)
    try:
        with open(text_path, "r", encoding="utf-8") as f:
            text = f.read()
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_font("Arial", size=12)
        for line in text.split('\n'):
            pdf.cell(0, 10, line, ln=True)
        pdf.output(output_pdf)
        print(f"Text file converted to PDF: {output_pdf}")
    except Exception as e:
        print(f"Error converting text to PDF: {e}")


def docx_to_pdf(docx_path, output_pdf=None):
    docx_path = clean_path(docx_path)
    if output_pdf:
        output_pdf = clean_path(output_pdf)
    try:
        if output_pdf is None:
            output_pdf = os.path.splitext(docx_path)[0] + ".pdf"
        docx2pdf_convert(docx_path, output_pdf)
        print(f"DOCX converted to PDF: {output_pdf}")
    except Exception as e:
        print(f"Error converting DOCX to PDF: {e}")


def pdf_to_docx(pdf_path, output_docx):
    # Complex: Not implemented
    print("PDF to DOCX conversion is currently not supported.")


def csv_to_excel(csv_path, output_xlsx):
    csv_path = clean_path(csv_path)
    output_xlsx = clean_path(output_xlsx)
    try:
        df = pd.read_csv(csv_path)
        df.to_excel(output_xlsx, index=False)
        print(f"CSV converted to Excel: {output_xlsx}")
    except Exception as e:
        print(f"Error converting CSV to Excel: {e}")


def excel_to_csv(xlsx_path, output_csv):
    xlsx_path = clean_path(xlsx_path)
    output_csv = clean_path(output_csv)
    try:
        df = pd.read_excel(xlsx_path)
        df.to_csv(output_csv, index=False)
        print(f"Excel converted to CSV: {output_csv}")
    except Exception as e:
        print(f"Error converting Excel to CSV: {e}")


def image_format_conversion(image_path, output_path):
    image_path = clean_path(image_path)
    output_path = clean_path(output_path)
    try:
        img = Image.open(image_path)
        img.save(output_path)
        print(f"Image converted: {output_path}")
    except Exception as e:
        print(f"Error converting image: {e}")


def file_conversion_menu():
    while True:
        print("""
File Conversion Options:
1. PDF to Images (PNG)
2. Images (PNG/JPG) to PDF
3. PDF to Text
4. Text to PDF
5. DOCX to PDF (Windows/Mac only)
6. CSV to Excel (XLSX)
7. Excel (XLSX) to CSV
8. Image Format Conversion (PNG/JPG/BMP/GIF)
9. Back to Main Menu
""")
        choice = input("Select option (1-9): ").strip()
        if choice == "1":
            pdf_path = input("Enter PDF file path: ")
            out_folder = input("Enter output folder for images: ")
            pdf_to_images(pdf_path, out_folder)
        elif choice == "2":
            imgs = input("Enter image file paths separated by comma: ").split(",")
            imgs = [img.strip() for img in imgs if img.strip()]
            out_pdf = input("Enter output PDF file path: ")
            images_to_pdf(imgs, out_pdf)
        elif choice == "3":
            pdf_path = input("Enter PDF file path: ")
            out_txt = input("Enter output text file path: ")
            pdf_to_text(pdf_path, out_txt)
        elif choice == "4":
            txt_path = input("Enter text file path: ")
            out_pdf = input("Enter output PDF file path: ")
            text_to_pdf(txt_path, out_pdf)
        elif choice == "5":
            docx_path = input("Enter DOCX file path: ")
            out_pdf = input("Enter output PDF file path (optional, press Enter to auto): ")
            if out_pdf.strip() == "":
                out_pdf = None
            docx_to_pdf(docx_path, out_pdf)
        elif choice == "6":
            csv_path = input("Enter CSV file path: ")
            out_xlsx = input("Enter output Excel file path: ")
            csv_to_excel(csv_path, out_xlsx)
        elif choice == "7":
            xlsx_path = input("Enter Excel file path: ")
            out_csv = input("Enter output CSV file path: ")
            excel_to_csv(xlsx_path, out_csv)
        elif choice == "8":
            img_path = input("Enter image file path: ")
            out_img_path = input("Enter output image path with extension (e.g. output.jpg): ")
            image_format_conversion(img_path, out_img_path)
        elif choice == "9":
            break
        else:
            print("Invalid choice, try again.")


def main_menu():
    while True:
        print("""
--- PDF & File Utility Menu ---
1. Show PDF Metadata
2. Split PDF
3. Merge PDFs
4. File Conversion
5. Exit
""")
        choice = input("Choose option (1-5): ").strip()

        if choice == "1":
            pdf_path = input("Enter PDF file path: ")
            show_pdf_metadata(pdf_path)
        elif choice == "2":
            pdf_path = input("Enter PDF file path: ")
            try:
                start = int(input("Enter start page number: "))
                end = int(input("Enter end page number: "))
            except ValueError:
                print("Please enter valid page numbers.")
                continue
            output = input("Enter output split PDF path: ")
            split_pdf(pdf_path, start, end, output)
        elif choice == "3":
            files = input("Enter PDF file paths to merge (comma separated): ").split(",")
            files = [f.strip() for f in files if f.strip()]
            output = input("Enter output merged PDF path: ")
            merge_pdfs(files, output)
        elif choice == "4":
            file_conversion_menu()
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid choice, try again.")


if __name__ == "__main__":
    main_menu()
