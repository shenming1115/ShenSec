"""Render ShenSec's code-defined shield icon; no external artwork or fonts."""
from pathlib import Path
import struct
from PySide6.QtCore import Qt, QBuffer, QIODevice
from PySide6.QtGui import QColor, QImage, QPainter, QPainterPath, QPen


def main():
    frames = []
    for size in (16, 32, 48, 64, 128, 256):
        image = QImage(size, size, QImage.Format_ARGB32)
        image.fill(Qt.transparent)
        painter = QPainter(image)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.scale(size / 256, size / 256)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#142333"))
        painter.drawRoundedRect(0, 0, 256, 256, 52, 52)
        shield = QPainterPath()
        shield.moveTo(128, 40)
        shield.lineTo(206, 70)
        shield.lineTo(199, 139)
        shield.cubicTo(194, 178, 158, 207, 128, 222)
        shield.cubicTo(98, 207, 62, 178, 57, 139)
        shield.lineTo(50, 70)
        shield.closeSubpath()
        painter.setBrush(QColor("#72dbc6"))
        painter.drawPath(shield)
        check = QPainterPath()
        check.moveTo(87, 126)
        check.lineTo(116, 155)
        check.lineTo(171, 98)
        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(QColor("#142333"), 18, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.drawPath(check)
        painter.end()
        buffer = QBuffer()
        buffer.open(QIODevice.WriteOnly)
        assert image.save(buffer, "PNG")
        frames.append((size, bytes(buffer.data())))
    offset = 6 + 16 * len(frames)
    header = struct.pack("<HHH", 0, 1, len(frames))
    for size, data in frames:
        header += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    target = Path(__file__).resolve().parents[1] / "src/shensec/resources/shensec.ico"
    target.write_bytes(header + b"".join(data for _, data in frames))


if __name__ == "__main__":
    main()
