import os
import urllib.request
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

BASE_URLS = [
    "https://mirror.ghproxy.com/https://github.com/malikshi/sing-box-geo/releases/latest/download/",
    "https://ghproxy.net/https://github.com/malikshi/sing-box-geo/releases/latest/download/",
    "https://github.com/malikshi/sing-box-geo/releases/latest/download/" # Fallback to direct download
]

FILES = ["geosite-ru.srs", "geoip-ru.srs"]

def download_file(filename, dest_path):
    for base_url in BASE_URLS:
        url = base_url + filename
        logging.info(f"Trying to download {filename} from {url} ...")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response, open(dest_path, 'wb') as out_file:
                out_file.write(response.read())
            logging.info(f"Successfully downloaded {filename} to {dest_path}")
            return True
        except Exception as e:
            logging.warning(f"Failed to download from {url}: {e}")
    return False

def main():
    # panel/rules directory
    rules_dir = os.path.join(os.path.dirname(__file__), "rules")
    os.makedirs(rules_dir, exist_ok=True)
    
    success = True
    for f in FILES:
        dest_path = os.path.join(rules_dir, f)
        if not download_file(f, dest_path):
            logging.error(f"CRITICAL ERROR: Could not download {f} from any mirror!")
            success = False
            
    if success:
        logging.info("All rule-sets updated successfully.")
        logging.info("Please restart sing-box to apply the new rules: sudo systemctl restart sing-box")
    else:
        logging.error("Failed to update some rule-sets.")
        exit(1)

if __name__ == "__main__":
    main()
