"""Program icons: extract the icon embedded in an .exe and return it as PNG bytes.

Used by the window (GET /api/icon) and the permission pop-ups. Results are cached in memory;
programs without an icon (or missing files, demo mode) return None so the UI shows letters.
"""
from __future__ import annotations

import io
import os
import threading
from collections import OrderedDict

SIZE = 48
_cache: "OrderedDict[str, bytes | None]" = OrderedDict()
_lock = threading.Lock()
_MAX = 600


def icon_png(path: str | None) -> bytes | None:
    if not path or os.name != "nt":
        return None
    key = os.path.normcase(os.path.abspath(path))
    with _lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]
    png = None
    if os.path.isabs(path) and os.path.isfile(path):
        try:
            png = _extract(path)
        except Exception:
            png = None
    with _lock:
        _cache[key] = png
        while len(_cache) > _MAX:
            _cache.popitem(last=False)
    return png


# --------------------------------------------------------------------------- Win32
def _api():
    import ctypes
    from ctypes import wintypes as W
    u32, g32 = ctypes.windll.user32, ctypes.windll.gdi32
    H = ctypes.c_void_p
    u32.PrivateExtractIconsW.argtypes = [W.LPCWSTR, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                         ctypes.POINTER(H), ctypes.POINTER(W.UINT), W.UINT, W.UINT]
    u32.PrivateExtractIconsW.restype = W.UINT
    u32.DrawIconEx.argtypes = [H, ctypes.c_int, ctypes.c_int, H, ctypes.c_int, ctypes.c_int, W.UINT, H, W.UINT]
    u32.DestroyIcon.argtypes = [H]
    g32.CreateCompatibleDC.argtypes = [H]
    g32.CreateCompatibleDC.restype = H
    g32.CreateDIBSection.argtypes = [H, ctypes.c_void_p, W.UINT, ctypes.POINTER(ctypes.c_void_p), H, W.DWORD]
    g32.CreateDIBSection.restype = H
    g32.SelectObject.argtypes = [H, H]
    g32.SelectObject.restype = H
    g32.DeleteObject.argtypes = [H]
    g32.DeleteDC.argtypes = [H]
    return ctypes, u32, g32


class _BIH:  # filled lazily (needs ctypes)
    t = None


def _bih_type(ctypes):
    if _BIH.t is None:
        from ctypes import wintypes as W

        class BITMAPINFOHEADER(ctypes.Structure):
            _fields_ = [("biSize", W.DWORD), ("biWidth", W.LONG), ("biHeight", W.LONG), ("biPlanes", W.WORD),
                        ("biBitCount", W.WORD), ("biCompression", W.DWORD), ("biSizeImage", W.DWORD),
                        ("biXPelsPerMeter", W.LONG), ("biYPelsPerMeter", W.LONG), ("biClrUsed", W.DWORD),
                        ("biClrImportant", W.DWORD)]
        _BIH.t = BITMAPINFOHEADER
    return _BIH.t


def _render(ctypes, u32, g32, hicon, flags):
    """Draw the icon into a top-down 32-bit DIB and return its BGRA bytes."""
    hdr = _bih_type(ctypes)(biSize=40, biWidth=SIZE, biHeight=-SIZE, biPlanes=1, biBitCount=32)
    bits = ctypes.c_void_p()
    dc = g32.CreateCompatibleDC(None)
    bmp = g32.CreateDIBSection(dc, ctypes.byref(hdr), 0, ctypes.byref(bits), None, 0)
    if not bmp or not bits.value:
        g32.DeleteDC(dc)
        return None
    old = g32.SelectObject(dc, bmp)
    try:
        ctypes.memset(bits, 0, SIZE * SIZE * 4)
        u32.DrawIconEx(dc, 0, 0, hicon, SIZE, SIZE, 0, None, flags)
        return ctypes.string_at(bits, SIZE * SIZE * 4)
    finally:
        g32.SelectObject(dc, old)
        g32.DeleteObject(bmp)
        g32.DeleteDC(dc)


def _extract(path: str) -> bytes | None:
    from PIL import Image
    ctypes, u32, g32 = _api()
    hicon = ctypes.c_void_p()
    icon_id = ctypes.c_uint()
    n = u32.PrivateExtractIconsW(path, 0, SIZE, SIZE, ctypes.byref(hicon), ctypes.byref(icon_id), 1, 0)
    if not n or n == 0xFFFFFFFF or not hicon.value:
        return None
    try:
        color = _render(ctypes, u32, g32, hicon, 0x0003)  # DI_NORMAL
        if not color:
            return None
        img = Image.frombuffer("RGBA", (SIZE, SIZE), color, "raw", "BGRA", 0, 1)
        if img.getextrema()[3][1] == 0:
            # old-style icon without an alpha channel: build alpha from its AND mask
            mask = _render(ctypes, u32, g32, hicon, 0x0001)  # DI_MASK (black = opaque)
            if not mask:
                return None
            m = Image.frombuffer("RGBA", (SIZE, SIZE), mask, "raw", "BGRA", 0, 1).convert("L")
            img = img.copy()
            img.putalpha(m.point(lambda v: 0 if v > 127 else 255))
        if img.getextrema()[3][1] == 0:
            return None
        out = io.BytesIO()
        img.save(out, "PNG", optimize=True)
        return out.getvalue()
    finally:
        u32.DestroyIcon(hicon)
