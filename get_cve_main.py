import subprocess
import csv
import time
import requests
from sys import exit
from platform import system as platform_name
from pick import pick


api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def open_file(filename):
    editors = {
        "Windows": "notepad.exe",
        "Linux": "gedit",
        "Darwin": "open -e"
    }
    if (editor := editors.get(platform_name())) is not None:
        editor_process = subprocess.Popen([editor, filename], shell=True)
        editor_process.communicate()
    else:
        print("[ERROR] Can't open editor. Please create a file with the CVE list manually.")


def start():
    with open("./cve_id.txt", "r") as file:
        input_cve_list = [line.strip() for line in file.readlines()]
    results = []
    delay = 6  # задержка перед запросом к API
    for i in range(len(input_cve_list)):
        print(f"Please wait {delay * (len(input_cve_list) - i)} s")
        response = requests.get(f"{api_url}?cveId={input_cve_list[i]}")
        if response.status_code == 200:
            results.append(response.json())
        else:
            print(f"{response.status_code} error\nFailed connection attempt with {api_url}?cveId={input_cve_list[i]}")
        time.sleep(delay)
    write_to_csv(results)


def write_to_csv(results):
    csv_filename = f"{time.strftime('%d-%m-%Y %H-%M-%S', time.gmtime())} result.csv"
    fieldnames = ["cve_id", "CVSSv2", "CVSSv3", "published", "description", "vector", "cpe"]
    with open(csv_filename, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for cve in results:
            if cve is not None:
                cve_data = cve["vulnerabilities"][0]["cve"]
                writer.writerow({"cve_id": cve_data["id"].strip(),
                                 "CVSSv2": cve_data["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"] \
                                     if "cvssMetricV2" in cve_data["metrics"] else "-",
                                 "CVSSv3": cve_data["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] \
                                     if "cvssMetricV31" in cve_data["metrics"] else "-",
                                 "published": cve_data["published"].strip(),
                                 "description": cve_data["descriptions"][0]["value"].strip(),
                                 "vector": cve_data["metrics"]["cvssMetricV31"][0]["cvssData"]["attackVector"].strip(),
                                 "cpe": cve_data["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"].strip()})

    open_file(csv_filename)


def main_menu():
    title = 'get_cves (https://nvd.nist.gov/) | author: Igumenshchev Vasily | github: 1g-v'
    options = ['Edit the CVE IDs list', 'Start', 'Exit']
    option, index = pick(options, title, indicator='=>', default_index=0)
    return index


def main():
    while True:
        match main_menu():
            case 0:
                open_file("./cve_id.txt")
            case 1:
                start()
            case 2:
                exit(0)
            case _:
                print("err")


if __name__ == "__main__":
    main()
