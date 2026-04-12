#!/bin/bash

# Script to help setup GeoIP database for Sentinel-RS
# MaxMind GeoLite2 databases require a free account and license key.

DATA_DIR="./data"
DB_FILE="$DATA_DIR/GeoLite2-Country.mmdb"

echo "=== Sentinel-RS GeoIP Setup ==="

if [ ! -d "$DATA_DIR" ]; then
    echo "Creating data directory..."
    mkdir -p "$DATA_DIR"
fi

if [ -f "$DB_FILE" ]; then
    echo "GeoIP database already exists at $DB_FILE"
    read -p "Do you want to redownload it? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

echo "To download the GeoLite2 database, you need a MaxMind Account."
echo "1. Register at: https://www.maxmind.com/en/geolite2/signup"
echo "2. Generate a License Key in your account dashboard."
echo

read -p "Enter your MaxMind License Key: " LICENSE_KEY

if [ -z "$LICENSE_KEY" ]; then
    echo "Error: License key is required for automated download."
    echo "You can also manually place 'GeoLite2-Country.mmdb' inside the '$DATA_DIR' folder."
    exit 1
fi

echo "Downloading GeoLite2-Country..."
# Using the direct download link pattern for MaxMind
URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=$LICENSE_KEY&suffix=tar.gz"

TEMP_DIR=$(mktemp -d)
curl -L "$URL" -o "$TEMP_DIR/geoip.tar.gz"

if [ $? -ne 0 ]; then
    echo "Failed to download database. Please check your license key."
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo "Extracting..."
tar -xzf "$TEMP_DIR/geoip.tar.gz" -C "$TEMP_DIR"
find "$TEMP_DIR" -name "GeoLite2-Country.mmdb" -exec cp {} "$DB_FILE" \;

rm -rf "$TEMP_DIR"

if [ -f "$DB_FILE" ]; then
    echo "Success! GeoIP database installed to $DB_FILE"
    echo "Restart Sentinel-RS to apply changes."
else
    echo "Extraction failed. GeoLite2-Country.mmdb not found in archive."
    exit 1
fi
