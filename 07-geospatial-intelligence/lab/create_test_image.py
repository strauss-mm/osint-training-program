#!/usr/bin/env python3
"""
Test Image Generator for GEOINT Lab

Creates a JPEG image with embedded EXIF metadata including GPS coordinates.
Default location is the Statue of Liberty (40.6892, -73.9857).

Usage:
    python create_test_image.py
    python create_test_image.py --lat 48.8584 --lon 2.2945 --output eiffel.jpg
"""

import argparse
import struct
import sys
from datetime import datetime, timezone

import piexif
from PIL import Image, ImageDraw, ImageFont


def decimal_to_dms_rational(decimal_degrees: float) -> tuple:
    """
    Convert decimal degrees to EXIF GPS rational format.

    EXIF GPS stores coordinates as three rational numbers: degrees, minutes,
    seconds -- each as a (numerator, denominator) tuple. We use 1000000 as
    the denominator for seconds to preserve precision.
    """
    is_negative = decimal_degrees < 0
    decimal_degrees = abs(decimal_degrees)

    degrees = int(decimal_degrees)
    minutes_float = (decimal_degrees - degrees) * 60
    minutes = int(minutes_float)
    seconds = (minutes_float - minutes) * 60

    # EXIF rational format: (numerator, denominator)
    # Using high denominator for seconds to maintain precision
    seconds_rational = (int(seconds * 1000000), 1000000)

    return ((degrees, 1), (minutes, 1), seconds_rational)


def create_test_image(
    output_path: str, latitude: float, longitude: float
) -> None:
    """Create a test JPEG with embedded GPS EXIF data."""

    # Create a simple gradient image with text
    width, height = 640, 480
    img = Image.new("RGB", (width, height))
    draw = ImageDraw.Draw(img)

    # Draw a gradient background (blue to green)
    for y in range(height):
        r = int(30 + (y / height) * 40)
        g = int(60 + (y / height) * 120)
        b = int(120 - (y / height) * 60)
        draw.line([(0, y), (width, y)], fill=(r, g, b))

    # Add text overlay
    text_lines = [
        "OSINT Training Program",
        "GEOINT Test Image",
        f"Lat: {latitude:.4f}",
        f"Lon: {longitude:.4f}",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
    ]

    # Use default font (monospace-like)
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 20)
    except (OSError, IOError):
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 20)
        except (OSError, IOError):
            font = ImageFont.load_default()

    y_pos = 100
    for line in text_lines:
        bbox = draw.textbbox((0, 0), line, font=font)
        text_width = bbox[2] - bbox[0]
        x_pos = (width - text_width) // 2
        # Drop shadow
        draw.text((x_pos + 2, y_pos + 2), line, fill=(0, 0, 0), font=font)
        # Main text
        draw.text((x_pos, y_pos), line, fill=(255, 255, 255), font=font)
        y_pos += 35

    # -----------------------------------------------------------------------
    # Build EXIF data
    #
    # EXIF is structured in IFDs (Image File Directories):
    #   - 0th IFD: basic image info (camera make/model, software)
    #   - Exif IFD: detailed capture info (datetime, exposure)
    #   - GPS IFD: geolocation data
    # -----------------------------------------------------------------------
    now_str = datetime.now(timezone.utc).strftime("%Y:%m:%d %H:%M:%S")

    # GPS coordinate conversion
    lat_dms = decimal_to_dms_rational(latitude)
    lon_dms = decimal_to_dms_rational(longitude)

    # GPS reference: N/S for latitude, E/W for longitude
    lat_ref = "N" if latitude >= 0 else "S"
    lon_ref = "E" if longitude >= 0 else "W"

    exif_dict = {
        "0th": {
            piexif.ImageIFD.Make: "OSINT Training Camera",
            piexif.ImageIFD.Model: "GEOINT Lab v1.0",
            piexif.ImageIFD.Software: "OSINT Training Program",
            piexif.ImageIFD.DateTime: now_str,
            piexif.ImageIFD.ImageWidth: width,
            piexif.ImageIFD.ImageLength: height,
            piexif.ImageIFD.Orientation: 1,
        },
        "Exif": {
            piexif.ExifIFD.DateTimeOriginal: now_str,
            piexif.ExifIFD.DateTimeDigitized: now_str,
            piexif.ExifIFD.ExposureTime: (1, 125),  # 1/125 second
            piexif.ExifIFD.FNumber: (28, 10),  # f/2.8
            piexif.ExifIFD.ISOSpeedRatings: 200,
            piexif.ExifIFD.FocalLength: (50, 1),  # 50mm
            piexif.ExifIFD.Flash: 0,  # No flash
            piexif.ExifIFD.ColorSpace: 1,  # sRGB
            piexif.ExifIFD.PixelXDimension: width,
            piexif.ExifIFD.PixelYDimension: height,
        },
        "GPS": {
            piexif.GPSIFD.GPSVersionID: (2, 3, 0, 0),
            piexif.GPSIFD.GPSLatitudeRef: lat_ref,
            piexif.GPSIFD.GPSLatitude: lat_dms,
            piexif.GPSIFD.GPSLongitudeRef: lon_ref,
            piexif.GPSIFD.GPSLongitude: lon_dms,
            piexif.GPSIFD.GPSAltitudeRef: 0,  # Above sea level
            piexif.GPSIFD.GPSAltitude: (10, 1),  # 10 meters
        },
    }

    exif_bytes = piexif.dump(exif_dict)

    # Save image with EXIF
    img.save(output_path, "JPEG", quality=95, exif=exif_bytes)

    print(f"[+] Test image created: {output_path}")
    print(f"    Dimensions: {width}x{height}")
    print(f"    GPS: {latitude}, {longitude} ({lat_ref}, {lon_ref})")
    print(f"    Camera: OSINT Training Camera / GEOINT Lab v1.0")
    print(f"    DateTime: {now_str}")
    print(f"    ISO: 200, Focal Length: 50mm, f/2.8, 1/125s")


def main():
    parser = argparse.ArgumentParser(
        description="Create a test JPEG image with embedded GPS EXIF metadata."
    )
    parser.add_argument(
        "--output",
        default="test_image.jpg",
        help="Output file path (default: test_image.jpg)",
    )
    parser.add_argument(
        "--lat",
        type=float,
        default=40.6892,
        help="Latitude in decimal degrees (default: 40.6892 -- Statue of Liberty)",
    )
    parser.add_argument(
        "--lon",
        type=float,
        default=-73.9857,
        help="Longitude in decimal degrees (default: -73.9857 -- Statue of Liberty)",
    )

    args = parser.parse_args()
    create_test_image(args.output, args.lat, args.lon)


if __name__ == "__main__":
    main()
