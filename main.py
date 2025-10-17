import argparse
from modules.xls_redactor import patch_xls

def main():
    parser = argparse.ArgumentParser(description="XLS SST 문자열 치환 도구")
    parser.add_argument("file")
    parser.add_argument("text")
    args = parser.parse_args()

    patch_xls(args.file, args.text)

if __name__ == "__main__":
    main()
