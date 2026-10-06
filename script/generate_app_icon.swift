#!/usr/bin/env swift
import AppKit
import Foundation

// Original NativeForensics artwork. A watchful hound and a lens refer to the
// investigation workflow without reproducing the Autopsy logo or its artwork.
let output = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? "Assets/AppIcon", isDirectory: true)
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

func color(_ hex: UInt32, alpha: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat((hex >> 16) & 255) / 255,
            green: CGFloat((hex >> 8) & 255) / 255,
            blue: CGFloat(hex & 255) / 255, alpha: alpha)
}

func shape(_ commands: [(String, [CGFloat])]) -> NSBezierPath {
    let path = NSBezierPath()
    for (command, values) in commands {
        switch command {
        case "M": path.move(to: NSPoint(x: values[0], y: values[1]))
        case "L": path.line(to: NSPoint(x: values[0], y: values[1]))
        case "C": path.curve(to: NSPoint(x: values[4], y: values[5]),
                             controlPoint1: NSPoint(x: values[0], y: values[1]),
                             controlPoint2: NSPoint(x: values[2], y: values[3]))
        case "Z": path.close()
        default: fatalError("Unknown vector command")
        }
    }
    return path
}

func fill(_ path: NSBezierPath, _ fill: NSColor) {
    fill.setFill()
    path.fill()
}

func gradient(_ path: NSBezierPath, _ from: UInt32, _ to: UInt32, angle: CGFloat = 90) {
    NSGradient(starting: color(from), ending: color(to))!.draw(in: path, angle: angle)
}

func drawIcon(size: Int) throws -> Data {
    guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
                                       bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                       isPlanar: false, colorSpaceName: .deviceRGB,
                                       bytesPerRow: size * 4, bitsPerPixel: 32),
          let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
        throw NSError(domain: "AppIcon", code: 1)
    }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = context
    context.imageInterpolation = .high
    context.cgContext.scaleBy(x: CGFloat(size) / 1024, y: CGFloat(size) / 1024)
    context.cgContext.translateBy(x: 0, y: 1024)
    context.cgContext.scaleBy(x: 1, y: -1)

    let tile = NSBezierPath(roundedRect: NSRect(x: 64, y: 64, width: 896, height: 896), xRadius: 196, yRadius: 196)
    NSGraphicsContext.saveGraphicsState()
    let shadow = NSShadow()
    shadow.shadowColor = color(0x061123, alpha: 0.22)
    shadow.shadowBlurRadius = 34
    shadow.shadowOffset = NSSize(width: 0, height: 14)
    shadow.set()
    gradient(tile, 0x203B56, 0x101D32)
    NSGraphicsContext.restoreGraphicsState()

    NSGraphicsContext.saveGraphicsState()
    tile.addClip()
    let glow = NSBezierPath(ovalIn: NSRect(x: 484, y: 188, width: 642, height: 642))
    fill(glow, color(0x2A98B8, alpha: 0.09))
    let horizon = NSBezierPath()
    horizon.move(to: NSPoint(x: 64, y: 784))
    horizon.curve(to: NSPoint(x: 960, y: 690), controlPoint1: NSPoint(x: 430, y: 630), controlPoint2: NSPoint(x: 715, y: 732))
    horizon.line(to: NSPoint(x: 960, y: 960)); horizon.line(to: NSPoint(x: 64, y: 960)); horizon.close()
    fill(horizon, color(0x081827, alpha: 0.18))
    NSGraphicsContext.restoreGraphicsState()
    color(0x7693AC, alpha: 0.25).setStroke()
    tile.lineWidth = 2; tile.stroke()

    // Upright ears, one flowing silhouette, and a broad muzzle keep the mark
    // legible at Dock and sidebar sizes rather than depending on fine lines.
    let hound = shape([
        ("M", [281, 421]), ("L", [279, 203]),
        ("C", [279, 183, 294, 180, 309, 197]), ("L", [399, 315]),
        ("C", [429, 300, 466, 293, 496, 296]),
        ("L", [596, 181]), ("C", [610, 165, 626, 172, 626, 194]),
        ("L", [632, 413]), ("C", [674, 457, 691, 520, 677, 575]),
        ("C", [664, 631, 634, 659, 611, 687]),
        ("L", [641, 774]), ("C", [581, 820, 396, 846, 268, 776]),
        ("L", [299, 684]), ("C", [263, 654, 237, 610, 238, 553]),
        ("C", [237, 500, 249, 455, 281, 421]), ("Z", [])
    ])
    NSGraphicsContext.saveGraphicsState()
    let dogShadow = NSShadow(); dogShadow.shadowColor = color(0x020A12, alpha: 0.35)
    dogShadow.shadowBlurRadius = 18; dogShadow.shadowOffset = NSSize(width: 0, height: 10); dogShadow.set()
    gradient(hound, 0x566373, 0x222A36)
    NSGraphicsContext.restoreGraphicsState()

    fill(shape([("M", [304, 238]), ("L", [375, 335]), ("L", [303, 405]), ("Z", [])]), color(0x121E2A))
    fill(shape([("M", [604, 222]), ("L", [531, 315]), ("L", [608, 398]), ("Z", [])]), color(0x17212E))
    fill(shape([
        ("M", [434, 315]), ("C", [465, 307, 491, 308, 512, 313]),
        ("L", [477, 507]), ("L", [446, 535]), ("L", [415, 503]), ("Z", [])
    ]), color(0x8290A0, alpha: 0.23))

    // Amber cheeks and chest retain the familiar forensic hound palette.
    gradient(shape([
        ("M", [260, 558]), ("C", [288, 528, 345, 547, 383, 578]),
        ("L", [440, 631]), ("L", [389, 697]),
        ("C", [321, 684, 261, 639, 260, 558]), ("Z", [])
    ]), 0xF0B968, 0xC87E32)
    gradient(shape([
        ("M", [484, 625]), ("L", [539, 579]),
        ("C", [579, 546, 633, 543, 667, 568]),
        ("C", [651, 640, 608, 685, 542, 696]), ("Z", [])
    ]), 0xEDB561, 0xBD7531)
    gradient(shape([
        ("M", [380, 694]), ("C", [407, 723, 462, 744, 510, 713]),
        ("L", [569, 792]), ("C", [511, 813, 397, 813, 337, 788]), ("Z", [])
    ]), 0xC38A48, 0x8E5E30)
    fill(shape([
        ("M", [398, 653]), ("C", [415, 675, 453, 686, 475, 660]),
        ("L", [484, 634]), ("L", [391, 632]), ("Z", [])
    ]), color(0x101923))
    gradient(shape([
        ("M", [369, 566]), ("C", [393, 551, 459, 552, 486, 573]),
        ("C", [484, 597, 460, 623, 428, 632]),
        ("C", [395, 617, 373, 594, 369, 566]), ("Z", [])
    ]), 0x263441, 0x111B27)

    let brows = [NSRect(x: 310, y: 454, width: 64, height: 27), NSRect(x: 526, y: 444, width: 62, height: 27)]
    for rect in brows { fill(NSBezierPath(roundedRect: rect, xRadius: 13, yRadius: 13), color(0xDFA257)) }
    fill(NSBezierPath(ovalIn: NSRect(x: 327, y: 491, width: 22, height: 17)), color(0xD9E6EC))
    fill(NSBezierPath(ovalIn: NSRect(x: 542, y: 481, width: 22, height: 17)), color(0xD9E6EC))

    // A substantial lens with a bright rim reads as an investigation tool at
    // small sizes. Its handle projects diagonally without breaking the tile.
    let handle = shape([
        ("M", [712, 707]), ("L", [846, 819]),
        ("C", [866, 836, 868, 854, 853, 871]),
        ("C", [837, 887, 817, 886, 799, 868]),
        ("L", [679, 738]), ("Z", [])
    ])
    NSGraphicsContext.saveGraphicsState()
    let lensShadow = NSShadow(); lensShadow.shadowColor = color(0x000A12, alpha: 0.35)
    lensShadow.shadowBlurRadius = 16; lensShadow.shadowOffset = NSSize(width: 0, height: 12); lensShadow.set()
    gradient(handle, 0x72DCE0, 0x278DB4, angle: 45)
    fill(NSBezierPath(ovalIn: NSRect(x: 473, y: 467, width: 286, height: 286)), color(0x91ECEB))
    NSGraphicsContext.restoreGraphicsState()
    let lens = NSBezierPath(ovalIn: NSRect(x: 492, y: 486, width: 248, height: 248))
    gradient(lens, 0x2E647A, 0x153C59, angle: 90)
    NSGraphicsContext.saveGraphicsState()
    lens.addClip()
    fill(NSBezierPath(ovalIn: NSRect(x: 517, y: 510, width: 187, height: 204)), color(0x5CCBD4, alpha: 0.17))
    fill(shape([
        ("M", [475, 523]), ("L", [663, 473]), ("L", [758, 516]),
        ("L", [511, 697]), ("Z", [])
    ]), color(0xB5F4F4, alpha: 0.15))
    NSGraphicsContext.restoreGraphicsState()
    color(0xC1FFFF, alpha: 0.70).setStroke(); lens.lineWidth = 3; lens.stroke()
    if size >= 64 {
        let glint = NSBezierPath()
        glint.move(to: NSPoint(x: 529, y: 587))
        glint.curve(to: NSPoint(x: 603, y: 529), controlPoint1: NSPoint(x: 540, y: 554), controlPoint2: NSPoint(x: 574, y: 527))
        color(0xDCFFFF, alpha: 0.80).setStroke(); glint.lineWidth = 11; glint.lineCapStyle = .round; glint.stroke()
    }
    NSGraphicsContext.restoreGraphicsState()
    guard let png = bitmap.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "AppIcon", code: 2)
    }
    return png
}

try drawIcon(size: 1024).write(to: output.appendingPathComponent("AppIcon.png"), options: .atomic)
let iconset = output.appendingPathComponent("generated-\(UUID().uuidString).iconset", isDirectory: true)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: false)
defer { try? FileManager.default.removeItem(at: iconset) }
for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let suffix = scale == 1 ? "" : "@2x"
        try drawIcon(size: points * scale).write(to: iconset.appendingPathComponent("icon_\(points)x\(points)\(suffix).png"))
    }
}
let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
process.arguments = ["--convert", "icns", "--output", output.appendingPathComponent("AppIcon.icns").path, iconset.path]
try process.run()
process.waitUntilExit()
guard process.terminationStatus == 0 else { throw NSError(domain: "AppIcon", code: Int(process.terminationStatus)) }
print("Generated original AppIcon.png and AppIcon.icns")
