# HexCore Icon Generator
# Generates all required icon assets from BatHexCoreTransparente.png
# Usage: powershell -ExecutionPolicy Bypass -File scripts/generate-hexcore-icons.ps1

Add-Type -AssemblyName System.Drawing

$src = Join-Path $PSScriptRoot "..\BatHexCoreTransparente.png"
if (-not (Test-Path $src)) {
    Write-Error "Source image not found: $src"
    exit 1
}

$srcImg = [System.Drawing.Image]::FromFile((Resolve-Path $src).Path)
Write-Host "Source: $($srcImg.Width)x$($srcImg.Height)"

function Resize-Png($img, $w, $h, $outPath) {
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $bmp.SetResolution(96, 96)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g.DrawImage($img, 0, 0, $w, $h)
    $g.Dispose()
    $dir = Split-Path $outPath -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "  Created: $outPath ($w x $h)"
}

function Resize-Bmp($img, $w, $h, $outPath, $bgColor) {
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $bmp.SetResolution(96, 96)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.Clear($bgColor)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    # Center the icon in the BMP with padding
    $scale = [Math]::Min($w / $img.Width, $h / $img.Height) * 0.7
    $iw = [int]($img.Width * $scale)
    $ih = [int]($img.Height * $scale)
    $x = [int](($w - $iw) / 2)
    $y = [int](($h - $ih) / 2)
    $g.DrawImage($img, $x, $y, $iw, $ih)
    $g.Dispose()
    $dir = Split-Path $outPath -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Bmp)
    $bmp.Dispose()
    Write-Host "  Created: $outPath ($w x $h BMP)"
}

$root = Join-Path $PSScriptRoot ".."

Write-Host "`n=== Generating PNG icons ==="

# Linux
Resize-Png $srcImg 512 512 (Join-Path $root "resources/linux/code.png")

# Server / PWA
Resize-Png $srcImg 512 512 (Join-Path $root "resources/server/code-512.png")
Resize-Png $srcImg 192 192 (Join-Path $root "resources/server/code-192.png")

# Windows tiles
Resize-Png $srcImg 150 150 (Join-Path $root "resources/win32/code_150x150.png")
Resize-Png $srcImg 70 70 (Join-Path $root "resources/win32/code_70x70.png")

# ICO sizes (will be assembled into .ico later)
$icoDir = Join-Path $root "resources/_ico_temp"
if (-not (Test-Path $icoDir)) { New-Item -ItemType Directory -Path $icoDir -Force | Out-Null }
Resize-Png $srcImg 256 256 (Join-Path $icoDir "256.png")
Resize-Png $srcImg 48 48 (Join-Path $icoDir "48.png")
Resize-Png $srcImg 32 32 (Join-Path $icoDir "32.png")
Resize-Png $srcImg 16 16 (Join-Path $icoDir "16.png")

Write-Host "`n=== Generating Installer BMPs ==="
$bgColor = [System.Drawing.Color]::FromArgb(255, 30, 30, 30)  # Dark background

# Inno big (sidebar)
$innoBigSizes = @(
    @{dpi=100; w=164; h=314},
    @{dpi=125; w=205; h=392},
    @{dpi=150; w=246; h=471},
    @{dpi=175; w=287; h=549},
    @{dpi=200; w=328; h=604},
    @{dpi=225; w=369; h=682},
    @{dpi=250; w=410; h=759}
)
foreach ($s in $innoBigSizes) {
    Resize-Bmp $srcImg $s.w $s.h (Join-Path $root "resources/win32/inno-big-$($s.dpi).bmp") $bgColor
}

# Inno small (top corner)
$innoSmallSizes = @(
    @{dpi=100; w=55; h=55},
    @{dpi=125; w=64; h=68},
    @{dpi=150; w=83; h=80},
    @{dpi=175; w=92; h=97},
    @{dpi=200; w=111; h=106},
    @{dpi=225; w=119; h=123},
    @{dpi=250; w=138; h=140}
)
foreach ($s in $innoSmallSizes) {
    Resize-Bmp $srcImg $s.w $s.h (Join-Path $root "resources/win32/inno-small-$($s.dpi).bmp") $bgColor
}

$srcImg.Dispose()

Write-Host "`n=== Done ==="
Write-Host "PNG and BMP icons generated."
Write-Host ""
Write-Host "REMAINING MANUAL STEPS:"
Write-Host "  1. Generate .ico from resources/_ico_temp/ PNGs"
Write-Host "     (use https://icoconvert.com or ImageMagick: magick convert 16.png 32.png 48.png 256.png code.ico)"
Write-Host "  2. Copy the .ico to resources/win32/code.ico and resources/server/favicon.ico"
Write-Host "  3. For macOS, generate .icns from the 1024x1024 source"
Write-Host "     (use iconutil on macOS or https://cloudconvert.com/png-to-icns)"
Write-Host "  4. Delete resources/_ico_temp/ after generating .ico"
