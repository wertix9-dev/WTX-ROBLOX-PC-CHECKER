Add-Type -AssemblyName System.Drawing

$sizes = 16, 24, 32, 48, 64, 128, 256
$images = @()

foreach ($size in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    $s = $size / 256.0
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddBezier([single](128*$s), [single](14*$s), [single](160*$s), [single](26*$s), [single](196*$s), [single](38*$s), [single](224*$s), [single](50*$s))
    $path.AddLine([single](224*$s), [single](50*$s), [single](224*$s), [single](124*$s))
    $path.AddBezier([single](224*$s), [single](124*$s), [single](224*$s), [single](184*$s), [single](184*$s), [single](226*$s), [single](128*$s), [single](244*$s))
    $path.AddBezier([single](128*$s), [single](244*$s), [single](72*$s), [single](226*$s), [single](32*$s), [single](184*$s), [single](32*$s), [single](124*$s))
    $path.AddLine([single](32*$s), [single](124*$s), [single](32*$s), [single](50*$s))
    $path.AddBezier([single](32*$s), [single](50*$s), [single](32*$s), [single](38*$s), [single](96*$s), [single](26*$s), [single](128*$s), [single](14*$s))
    $path.CloseFigure()

    $fill = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 17, 24, 29))
    $g.FillPath($fill, $path)
    $penWidth = [Math]::Max(1.6, 11*$s)
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 47, 212, 196), [single]$penWidth)
    $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $g.DrawPath($pen, $path)

    if ($size -ge 32) {
        $scanPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 47, 212, 196), [single]([Math]::Max(1.4, 10*$s)))
        $scanPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $scanPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
        $g.DrawLine($scanPen, [single](64*$s), [single](126*$s), [single](192*$s), [single](126*$s))
        $lime = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 166, 226, 46))
        $g.FillEllipse($lime, [single](109*$s), [single](160*$s), [single](38*$s), [single](38*$s))
        $scanPen.Dispose(); $lime.Dispose()
    } else {
        $lime = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 166, 226, 46))
        $g.FillRectangle($lime, [single](96*$s), [single](120*$s), [single](64*$s), [single](16*$s))
        $lime.Dispose()
    }

    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $images += ,$ms.ToArray()
    $ms.Dispose(); $pen.Dispose(); $fill.Dispose(); $path.Dispose(); $g.Dispose(); $bmp.Dispose()
}

$out = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($out)
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]
    $data = $images[$i]
    $bw.Write([byte]($(if ($sz -ge 256) { 0 } else { $sz })))
    $bw.Write([byte]($(if ($sz -ge 256) { 0 } else { $sz })))
    $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([UInt16]1); $bw.Write([UInt16]32)
    $bw.Write([UInt32]$data.Length); $bw.Write([UInt32]$offset)
    $offset += $data.Length
}
foreach ($data in $images) { $bw.Write($data) }
$bw.Flush()
[System.IO.File]::WriteAllBytes((Join-Path (Get-Location) "src\WTX-PC-CHECK\Assets\AppIcon.ico"), $out.ToArray())
$bw.Dispose(); $out.Dispose()
Write-Output ("Icon written: {0:N0} bytes" -f (Get-Item "src\WTX-PC-CHECK\Assets\AppIcon.ico").Length)

