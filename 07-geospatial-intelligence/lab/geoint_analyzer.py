#!/usr/bin/env python3
"""
GEOINT Image Analyzer

Extracts EXIF metadata from images, reverse geocodes GPS coordinates using
OpenStreetMap Nominatim, and generates a Markdown report and interactive
HTML map using folium.

Usage:
    python geoint_analyzer.py --image photo.jpg
    python geoint_analyzer.py --image photo.jpg --output-dir ./results --no-map
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import folium
import requests
from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS

# Nominatim usage policy: max 1 req/sec, descriptive User-Agent required
# https://operations.osmfoundation.org/policies/nominatim/
NOMINATIM_USER_AGENT = "OSINT-Training-GEOINT-Lab/1.0"


def get_exif_data(image_path: str) -> dict:
    """
    Extract all EXIF metadata from an image file.

    EXIF (Exchangeable Image File Format) is a standard that specifies formats
    for images and ancillary tags used by digital cameras and phones. Key fields
    include camera make/model, timestamps, GPS coordinates, and exposure settings.
    """
    try:
        img = Image.open(image_path)
    except Exception as e:
        print(f"[!] Cannot open image: {e}", file=sys.stderr)
        return {}

    exif_raw = img.getexif()
    if not exif_raw:
        return {}

    exif_data = {}
    for tag_id, value in exif_raw.items():
        tag_name = TAGS.get(tag_id, str(tag_id))
        exif_data[tag_name] = value

    # Process GPSInfo separately -- it's a nested IFD
    gps_info = exif_raw.get_ifd(0x8825)  # GPSInfo IFD pointer
    if gps_info:
        gps_data = {}
        for tag_id, value in gps_info.items():
            tag_name = GPSTAGS.get(tag_id, str(tag_id))
            gps_data[tag_name] = value
        exif_data["GPSInfo"] = gps_data

    return exif_data


def gps_dms_to_decimal(dms_tuple, ref: str) -> float | None:
    """
    Convert EXIF GPS DMS (degrees, minutes, seconds) to decimal degrees.

    EXIF stores GPS as three IFDRational values: (degrees, minutes, seconds).
    Each rational is a fraction (numerator/denominator). The reference (N/S/E/W)
    determines the sign.

    Example: 40 deg 41' 21.12" N = 40 + 41/60 + 21.12/3600 = 40.6892
    """
    try:
        degrees = float(dms_tuple[0])
        minutes = float(dms_tuple[1])
        seconds = float(dms_tuple[2])

        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)

        if ref in ("S", "W"):
            decimal = -decimal

        return decimal
    except (TypeError, IndexError, ZeroDivisionError):
        return None


def decimal_to_dms_string(decimal: float, is_latitude: bool) -> str:
    """Convert decimal degrees to a human-readable DMS string."""
    direction = ""
    if is_latitude:
        direction = "N" if decimal >= 0 else "S"
    else:
        direction = "E" if decimal >= 0 else "W"

    decimal = abs(decimal)
    degrees = int(decimal)
    minutes_float = (decimal - degrees) * 60
    minutes = int(minutes_float)
    seconds = (minutes_float - minutes) * 60

    return f'{degrees} deg {minutes}\' {seconds:.2f}" {direction}'


def reverse_geocode(lat: float, lon: float) -> dict | None:
    """
    Reverse geocode coordinates to an address using OpenStreetMap Nominatim.

    Nominatim is a free geocoding service. Usage policy requires:
    - Maximum 1 request per second
    - A descriptive User-Agent header
    - No heavy bulk usage
    """
    url = "https://nominatim.openstreetmap.org/reverse"
    params = {"format": "json", "lat": lat, "lon": lon, "zoom": 18}
    headers = {"User-Agent": NOMINATIM_USER_AGENT}

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        else:
            print(
                f"  [Nominatim] HTTP {resp.status_code}", file=sys.stderr
            )
            return None
    except requests.exceptions.RequestException as e:
        print(f"  [Nominatim] Error: {e}", file=sys.stderr)
        return None


def generate_map(
    lat: float, lon: float, metadata: dict, output_path: str
) -> None:
    """
    Generate an interactive HTML map using folium (Leaflet.js wrapper).

    The map includes:
    - A marker at the GPS coordinates
    - A popup with key metadata
    - A circle overlay showing approximate area
    """
    m = folium.Map(location=[lat, lon], zoom_start=15)

    # Build popup content
    popup_lines = [f"<b>Coordinates:</b> {lat:.6f}, {lon:.6f}"]
    if metadata.get("address"):
        popup_lines.append(f"<b>Address:</b> {metadata['address']}")
    if metadata.get("camera"):
        popup_lines.append(f"<b>Camera:</b> {metadata['camera']}")
    if metadata.get("datetime"):
        popup_lines.append(f"<b>DateTime:</b> {metadata['datetime']}")

    popup_html = "<br>".join(popup_lines)

    folium.Marker(
        location=[lat, lon],
        popup=folium.Popup(popup_html, max_width=300),
        tooltip="Click for details",
        icon=folium.Icon(color="red", icon="camera", prefix="fa"),
    ).add_to(m)

    # Add a circle overlay for visual reference
    folium.Circle(
        location=[lat, lon],
        radius=100,
        color="red",
        fill=True,
        fill_opacity=0.1,
    ).add_to(m)

    m.save(output_path)


def generate_report(
    image_path: str,
    exif_data: dict,
    lat: float | None,
    lon: float | None,
    address_data: dict | None,
    output_dir: str,
) -> str:
    """Generate a Markdown GEOINT analysis report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    file_name = os.path.basename(image_path)
    file_size = os.path.getsize(image_path)

    lines = [
        "# GEOINT Analysis Report",
        "",
        f"**File:** {file_name}",
        f"**Analysis Date:** {now}",
        "",
        "---",
        "",
        "## File Information",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| File Name | {file_name} |",
        f"| File Size | {file_size:,} bytes |",
        f"| Format | {exif_data.get('ImageWidth', 'N/A')}x{exif_data.get('ImageLength', 'N/A')} |",
        "",
    ]

    # Camera / device information
    lines.extend(
        [
            "## Camera / Device Information",
            "",
            "| Field | Value |",
            "|-------|-------|",
        ]
    )
    camera_fields = [
        ("Make", "Make"),
        ("Model", "Model"),
        ("Software", "Software"),
        ("Orientation", "Orientation"),
        ("DateTime", "DateTime"),
        ("DateTimeOriginal", "DateTimeOriginal"),
        ("ExposureTime", "ExposureTime"),
        ("FNumber", "FNumber"),
        ("ISOSpeedRatings", "ISOSpeedRatings"),
        ("FocalLength", "FocalLength"),
        ("Flash", "Flash"),
    ]
    for label, key in camera_fields:
        val = exif_data.get(key, "Not present")
        lines.append(f"| {label} | {val} |")
    lines.append("")

    # GPS analysis
    lines.extend(["## GPS Analysis", ""])

    if lat is not None and lon is not None:
        lat_dms = decimal_to_dms_string(lat, is_latitude=True)
        lon_dms = decimal_to_dms_string(lon, is_latitude=False)

        lines.extend(
            [
                "| Format | Latitude | Longitude |",
                "|--------|----------|-----------|",
                f"| Decimal Degrees | {lat:.6f} | {lon:.6f} |",
                f"| DMS | {lat_dms} | {lon_dms} |",
                "",
            ]
        )

        # Reverse geocoded address
        if address_data:
            display_name = address_data.get("display_name", "N/A")
            lines.extend(
                [
                    "### Reverse Geocoded Address",
                    "",
                    f"{display_name}",
                    "",
                ]
            )

        # Map links
        lines.extend(
            [
                "### External Map Links",
                "",
                f"- [Google Maps](https://www.google.com/maps?q={lat},{lon})",
                f"- [OpenStreetMap](https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=15)",
                "",
            ]
        )

        # Link to generated map
        map_filename = Path(file_name).stem + "_map.html"
        lines.extend(
            [
                f"### Generated Map",
                "",
                f"See [{map_filename}]({map_filename}) for interactive map.",
                "",
            ]
        )
    else:
        lines.extend(["*No GPS coordinates found in image metadata.*", ""])

    # OPSEC note
    lines.extend(
        [
            "---",
            "",
            "## OPSEC Implications",
            "",
            "Image metadata can reveal:",
            "- **Location** -- exact GPS coordinates where the photo was taken",
            "- **Device** -- camera make/model identifies the hardware",
            "- **Time** -- when the photo was captured",
            "- **Software** -- editing tools used post-capture",
            "",
            "Always strip metadata before sharing images publicly. Most social media",
            "platforms do this automatically, but messaging apps and cloud storage may not.",
            "",
            "---",
            "",
            "*Generated by OSINT Training Program - Module 07*",
        ]
    )

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Extract EXIF metadata from images, reverse geocode GPS "
        "coordinates, and generate analysis reports with interactive maps."
    )
    parser.add_argument(
        "--image", required=True, help="Path to the image file to analyze"
    )
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Directory for output files (default: ./output)",
    )
    parser.add_argument(
        "--no-map",
        action="store_true",
        help="Skip HTML map generation",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.image):
        print(f"[!] File not found: {args.image}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"[*] Analyzing: {args.image}", file=sys.stderr)

    # Extract EXIF
    print("[*] Extracting EXIF metadata...", file=sys.stderr)
    exif_data = get_exif_data(args.image)

    if not exif_data:
        print("[!] No EXIF metadata found in image.", file=sys.stderr)
        print("    The image may have been stripped of metadata.", file=sys.stderr)

    # Extract GPS coordinates
    lat, lon = None, None
    gps_info = exif_data.get("GPSInfo", {})

    if gps_info:
        lat_dms = gps_info.get("GPSLatitude")
        lat_ref = gps_info.get("GPSLatitudeRef", "N")
        lon_dms = gps_info.get("GPSLongitude")
        lon_ref = gps_info.get("GPSLongitudeRef", "E")

        if lat_dms and lon_dms:
            lat = gps_dms_to_decimal(lat_dms, lat_ref)
            lon = gps_dms_to_decimal(lon_dms, lon_ref)
            if lat is not None and lon is not None:
                print(f"    GPS: {lat:.6f}, {lon:.6f}", file=sys.stderr)
            else:
                print("    GPS: Could not parse coordinates.", file=sys.stderr)
        else:
            print("    GPS: Partial data -- coordinates incomplete.", file=sys.stderr)
    else:
        print("    GPS: No GPS data found.", file=sys.stderr)

    # Camera info summary
    make = exif_data.get("Make", "Unknown")
    model = exif_data.get("Model", "Unknown")
    dt = exif_data.get("DateTime", exif_data.get("DateTimeOriginal", "Unknown"))
    print(f"    Camera: {make} / {model}", file=sys.stderr)
    print(f"    DateTime: {dt}", file=sys.stderr)

    # Reverse geocode
    address_data = None
    if lat is not None and lon is not None:
        print("[*] Reverse geocoding via Nominatim...", file=sys.stderr)
        address_data = reverse_geocode(lat, lon)
        if address_data:
            print(
                f"    Address: {address_data.get('display_name', 'N/A')}",
                file=sys.stderr,
            )
        else:
            print("    Could not reverse geocode.", file=sys.stderr)

    # Generate map
    file_stem = Path(args.image).stem
    if lat is not None and lon is not None and not args.no_map:
        map_path = os.path.join(args.output_dir, f"{file_stem}_map.html")
        print(f"[*] Generating map: {map_path}", file=sys.stderr)
        metadata_for_map = {
            "address": address_data.get("display_name") if address_data else None,
            "camera": f"{make} / {model}",
            "datetime": dt,
        }
        generate_map(lat, lon, metadata_for_map, map_path)

    # Generate report
    report = generate_report(
        args.image, exif_data, lat, lon, address_data, args.output_dir
    )
    report_path = os.path.join(args.output_dir, f"{file_stem}_report.md")
    with open(report_path, "w") as f:
        f.write(report)
    print(f"[+] Report saved: {report_path}", file=sys.stderr)

    # Also print report to stdout
    print()
    print(report)


if __name__ == "__main__":
    main()
