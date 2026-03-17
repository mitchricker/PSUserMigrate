function ConvertTo-PlainText {
    param (
        [Parameter(Mandatory)]
        [SecureString]$SecureString
    )

    return [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    )
}