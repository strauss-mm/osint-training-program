# Lab 07: Image Metadata Extraction and Geolocation

**Difficulty:** Intermediate
**Estimated Time:** 90 minutes
**Prerequisites:** Python 3.9+, internet access for Nominatim API

---

## Objectives

- Create a test image with embedded GPS EXIF data
- Extract and interpret EXIF metadata programmatically
- Reverse geocode GPS coordinates to a physical address
- Generate an interactive HTML map from image metadata
- Understand OPSEC implications of image metadata

## Setup

```bash
cd /Users/mmstrauss/dev/osint-training-program/07-geospatial-intelligence/lab
pip install -r requirements.txt
```

## Exercise 1: Create a Test Image

Generate a sample JPEG with embedded GPS coordinates (Statue of Liberty):

```bash
python create_test_image.py
```

This creates `test_image.jpg` with EXIF data including GPS coordinates, camera model, and
timestamps. You can customize the location:

```bash
python create_test_image.py --lat 48.8584 --lon 2.2945 --output eiffel_tower.jpg
```

## Exercise 2: Run the GEOINT Analyzer

Analyze the test image:

```bash
python geoint_analyzer.py --image test_image.jpg
```

Review the terminal output. The script extracts:
- Camera/device information
- GPS coordinates (both DMS and decimal degree formats)
- Reverse geocoded address from OpenStreetMap
- Timestamps and other metadata

## Exercise 3: Examine the HTML Map

The analyzer generates an HTML map in the output directory:

```bash
open output/test_image_map.html    # macOS
```

Examine the map marker and popup. The marker shows the exact coordinates with metadata
in the popup.

## Exercise 4: Review the Markdown Report

```bash
cat output/test_image_report.md
```

Note the structure: file information, camera details, GPS analysis, and links to
mapping services. This format is suitable for inclusion in investigation reports.

## Exercise 5: Test with Your Own Photos

Try the analyzer against photos from your own camera or phone. Note:

- Photos taken with smartphones typically include GPS if location services are enabled.
- Screenshots generally do not contain GPS data.
- Photos downloaded from social media have usually been stripped of EXIF by the platform.
- Photos from messaging apps (Signal, WhatsApp) may or may not retain EXIF.

```bash
python geoint_analyzer.py --image /path/to/your/photo.jpg
```

## Exercise 6: OPSEC Discussion

Consider these questions based on your findings:

1. What information could an adversary extract from a photo you posted online?
2. Which messaging and social platforms strip EXIF metadata?
3. How would you verify that a photo's GPS data has not been spoofed?
4. What is the difference between a photo taken at a location vs. a photo with GPS data
   claiming that location?

## Challenge Exercises

### Challenge A: Batch Processing

Modify `geoint_analyzer.py` to accept a directory path and process all images, generating
a summary report with a map showing all geotagged locations.

### Challenge B: Sun Position Analysis

Using the `suncalc` Python library or the SunCalc algorithm, estimate whether the shadows
in a photo are consistent with the timestamp and GPS location in its EXIF data.

### Challenge C: Metadata Comparison

Write a script that compares EXIF data across multiple images to determine if they were
taken by the same device, at the same location, or within the same time window.

## Cleanup

```bash
rm -f test_image.jpg eiffel_tower.jpg
rm -rf output/
```

## Key Takeaways

- Image metadata is one of the most underestimated sources of intelligence. A single
  photo can reveal the device, location, time, and software used.
- EXIF data is trivially extractable but also trivially spoofable -- always corroborate.
- The Nominatim API is free but rate-limited; respect the usage policy.
- Metadata stripping by platforms is a privacy feature, not a guarantee.
