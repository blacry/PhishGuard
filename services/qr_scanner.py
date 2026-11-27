"""QR decoding for uploaded image files."""

from io import BytesIO

import cv2
import numpy as np
from PIL import Image, UnidentifiedImageError


def decode_qr(uploaded_file, max_bytes=5 * 1024 * 1024):
    """Decode one QR code from a PNG or JPEG upload; never open its contents."""
    raw = uploaded_file.read(max_bytes + 1)
    if len(raw) > max_bytes:
        return {"ok": False, "error": "Image is larger than the 5 MB upload limit."}
    try:
        image = Image.open(BytesIO(raw))
        if image.format not in {"PNG", "JPEG"}:
            return {"ok": False, "error": "Upload a PNG or JPG image."}
        if image.width * image.height > 25_000_000:
            return {"ok": False, "error": "Image dimensions are too large to process safely."}
        pixels = cv2.cvtColor(np.array(image.convert("RGB")), cv2.COLOR_RGB2BGR)
        detector = cv2.QRCodeDetector()
        text, points, _ = detector.detectAndDecode(pixels)
        if not text:
            return {"ok": False, "error": "No readable QR code was found. Multiple codes in one image may not be supported by this OpenCV build."}
        return {"ok": True, "text": text, "points": points}
    except (UnidentifiedImageError, OSError, cv2.error, ValueError):
        return {"ok": False, "error": "The uploaded file could not be read as a valid image."}
