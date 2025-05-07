import argparse 
from scanner.headers import analyze_headers
from scanner.cookies import analyze_cookies
from scanner.xss import test_xss
import os

REPORT_PATH="reports/scan_reports.txt"

def main():
    parser=argparse.ArgumentParser(description="Web vulnerabilities Scanner(mini-Zap)")
    parser.add_argument("--url",required=True, help="Traget URL (e.g.,https:/example.com)")
    args= parser.parse_args()

    url= args.url 

    if not os.path.exists("reports"):
        os.makedirs("reports")
    with open(REPORT_PATH,"w") as report:
        report.write(f"Scanning URL :{url}\n\n")
        report.write("---HTTP Security Headers ---\n")
        headers_report =analyze_headers(url)
        report.write(headers_report + "\n")

        report.write("--- Reflected XSS Testing ---\n")
        xss_report=test_xss(url)
        report.write(xss_report + "\n")
    print(f"Scan Complete.Report saved to {REPORT_PATH}")
if __name__ =="__main__":
    main()