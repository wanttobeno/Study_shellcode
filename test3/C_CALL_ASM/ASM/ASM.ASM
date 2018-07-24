.386
.model flat, c



.code 

public AsmShellData
public AsmChar
public hellohhl

AsmShellData proc
sztext2 db	'hellohhlAsmShellData',0
byte 2000 dup (8)
AsmShellData endp



AsmChar proc
byte 2000 dup (6)
AsmChar endp



hellohhl proc
sztext db	'hellohhl',0
hellohhl endp


end


