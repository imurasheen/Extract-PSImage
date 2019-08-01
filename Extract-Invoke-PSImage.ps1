function Extract-Invoke-PSImage
{
<#
[Description]
Extract the payload(Powershell Script) embedded by Invoke-PSImage from malicious PNG image file.
[Author]
imurasheen
[PARAMETER]
Image  The image to analyse..
Out    The file to save the resulting payload(embedded Powershell Script).
[EXAMPLE]
PS>Import-Module .\Extract-Invoke-PSImage.ps1
PS>Extract-Invoke-PSImage -Image .\malicious.png -Out .\result.ps1
   [First 50 characters of the extracted payload]
   [Oneliner to extract the payload from a file]

#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $Image,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $Out
    )
    # Stop if we hit an error instead of making more errors
    $ErrorActionPreference = "Stop"

    # Load some assemblies
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

    # Normalize paths beacuse powershell is sometimes bad with them.
    if (-Not [System.IO.Path]::IsPathRooted($Image)){
        $Image = [System.IO.Path]::GetFullPath((Join-Path (pwd) $Image))
    }
    if (-Not [System.IO.Path]::IsPathRooted($Out)){
        $Out = [System.IO.Path]::GetFullPath((Join-Path (pwd) $Out))
    }

    # Read the image into a bitmap
    $img = New-Object System.Drawing.Bitmap($Image)

    $width = $img.Size.Width
    $height = $img.Size.Height


    # To get the maximam length of the payload which can be embedded into the malicious image.
    $rect = New-Object System.Drawing.Rectangle(0, 0, $width, $height);
    $bmpData = $img.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadWrite, $img.PixelFormat)
    $lmaxpayload  = [Math]::Abs($bmpData.Stride) * $img.Height / 2
    $img.UnlockBits($bmpData)
    $img.Dispose()


    # Get the parameter to make the extractor 
    $rows = [math]::Ceiling($lmaxpayload/$width)
    $array = ($rows*$width)
    #$lrows = ($rows-1)  Because it is too large value to analyze the image...
    $lrows = ($height-1)
    $lwidth = ($width-1)
    $lpayload = ($lmaxpayload-1)

    #variable for output the result
    $payload = ""
    $result = ""
    
    $pscmd = "sal a New-Object;Add-Type -AssemblyName `"System.Drawing`";`$g=a System.Drawing.Bitmap(`"$Image`");`$o=a Byte[] $array;(0..$lrows)|%{foreach(`$x in(0..$lwidth)){`$p=`$g.GetPixel(`$x,`$_);`$o[`$_*$width+`$x]=([math]::Floor((`$p.B-band15)*16)-bor(`$p.G-band15))}};`$g.Dispose();[System.Text.Encoding]::ASCII.GetString(`$o[0..$lpayload])|Out-File `$Out"
    
    #It is different from above $pscmd. Because extracted payload is used in the following process.
    iex("sal a New-Object;Add-Type -AssemblyName `"System.Drawing`";`$g=a System.Drawing.Bitmap(`"$Image`");`$o=a Byte[] $array;(0..$lrows)|%{foreach(`$x in(0..$lwidth)){`$p=`$g.GetPixel(`$x,`$_);`$o[`$_*$width+`$x]=([math]::Floor((`$p.B-band15)*16)-bor(`$p.G-band15))}};`$g.Dispose();`$payload=[System.Text.Encoding]::ASCII.GetString(`$o[0..$lpayload])")
    #iex($pscmd)
    Out-File $Out -inputobject $payload


    $result = "[Oneliner to extract embedded payload]`r`n"
    $result += $pscmd
    $result += "`r`n"
    $result += "[First 50 characters of extracted payload]`r`n"
    $result += $payload.Substring(0,50)
    
    return $result
}
