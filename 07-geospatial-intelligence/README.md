# Module 07: Geospatial Intelligence (GEOINT)

## Overview

Geospatial intelligence involves the analysis of imagery, location data, and geographic
information to extract investigative leads. This module focuses on image metadata extraction
(EXIF), reverse geocoding, and geographic visualization -- skills that are foundational to
modern OSINT investigations, from verifying conflict zone imagery to tracking asset locations.

## Learning Objectives

- Extract and interpret EXIF metadata from image files
- Convert GPS coordinates between DMS (degrees/minutes/seconds) and decimal degrees
- Perform reverse geocoding to identify physical addresses from coordinates
- Generate interactive geographic visualizations
- Understand how metadata leaks compromise operational security

## Prerequisites

- Python 3.9+
- Modules 01-06 completed
- Internet access (for Nominatim reverse geocoding API)

## Key Concepts

| Concept | Description |
|---------|-------------|
| EXIF metadata | Exchangeable Image File Format data embedded in photos by cameras/phones |
| GPS coordinates | Latitude/longitude pairs encoded in EXIF GPSInfo tags |
| DMS vs DD | Degrees-Minutes-Seconds (40 41'21"N) vs Decimal Degrees (40.6892) |
| Reverse geocoding | Converting coordinates to a human-readable address |
| Chronolocation | Using sun position and shadows to estimate when a photo was taken |
| Geolocation verification | Cross-referencing image content with map/satellite data |
| Metadata stripping | Social platforms removing EXIF on upload (Instagram, Twitter, Facebook) |

## Tool Reference

| Tool | Description | Link |
|------|-------------|------|
| ExifTool | Industry-standard metadata reader/writer | https://exiftool.org/ |
| Pillow | Python imaging library with EXIF support | https://pillow.readthedocs.io/ |
| piexif | Pure Python EXIF manipulation library | https://github.com/hMatoba/Piexif |
| folium | Python library for Leaflet.js map generation | https://python-visualization.github.io/folium/ |
| Google Earth Pro | Free geographic information application | https://www.google.com/earth/about/versions/#earth-pro |
| Nominatim | OpenStreetMap geocoding/reverse geocoding API | https://nominatim.org/release-docs/latest/api/Overview/ |
| SunCalc | Sun position and light phases calculator | https://github.com/mourner/suncalc |
| Sentinel Hub | Copernicus satellite imagery access | https://www.sentinel-hub.com/ |
| GeoSpy | AI-powered geolocation from images | https://geospy.ai/ |
| Bellingcat Toolkit | Investigation tools maintained by Bellingcat | https://www.bellingcat.com/category/resources/ |

## Important Notes

- **Nominatim usage policy:** Maximum 1 request per second, include a descriptive
  User-Agent header, do not bulk-geocode. See https://operations.osmfoundation.org/policies/nominatim/
- Many social media platforms strip EXIF data on upload. Original files (from messaging
  apps, email, cloud storage) are more likely to retain metadata.
- EXIF data can be spoofed. Always corroborate with other evidence.

## Further Reading

- Bellingcat's geolocation guides: https://www.bellingcat.com/category/resources/how-tos/
- ExifTool tag documentation: https://exiftool.org/TagNames/
- OpenStreetMap Nominatim documentation
- Copernicus Open Access Hub: https://scihub.copernicus.eu/

## Lab

Proceed to [lab/LAB.md](lab/LAB.md) for the hands-on exercise.
