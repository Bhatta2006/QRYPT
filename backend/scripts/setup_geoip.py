import os
import urllib.request
import tarfile

def download_geoip_test_db():
    url = "https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoIP2-City-Test.mmdb"
    os.makedirs("/app/data", exist_ok=True)
    db_path = "/app/data/GeoLite2-City.mmdb"
    print(f"Downloading {url} to {db_path}...")
    urllib.request.urlretrieve(url, db_path)
    print("Download complete.")

if __name__ == "__main__":
    download_geoip_test_db()
