rule Embedded_PE
{
    meta:
        description = "Second MZ with a plausible PE header - carrier or dropper"
        severity = "medium"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and #mz > 1 and
        for any i in (2..#mz) : (
            @mz[i] > 0x200 and
            $pe in (@mz[i] + 0x3c .. @mz[i] + 0x200)
        )
}

rule Injection_API_Combo
{
    meta:
        description = "Allocation plus remote-write plus remote-thread trio"
        severity = "high"
    strings:
        $a = "VirtualAllocEx" ascii nocase
        $b = "WriteProcessMemory" ascii nocase
        $c = "CreateRemoteThread" ascii nocase
    condition:
        all of them
}

rule Base64_Blob
{
    meta:
        description = "Long base64 run - possible encoded payload"
        severity = "low"
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
    condition:
        $b64
}
