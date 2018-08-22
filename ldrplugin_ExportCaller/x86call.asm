OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

.686
.MODEL FLAT, C
.STACK

.DATA
	
.CODE
x86call PROC targetAddr:DWORD, argsMem:DWORD, szArgs:DWORD
	push ebp
	mov ebp, esp
	push edi
	push esi
	push ecx
	push 0BADF00Dh
	mov esi, [ebp + 0Ch]
	mov ecx, [ebp + 10h]
	sub esp, [ebp + 10h]
	mov edi, esp
	rep movsb
	call dword ptr [ebp + 8]
	cmp dword ptr [esp], 0BADF00Dh
	je @stdcall
	add esp, [ebp + 10h]
@stdcall:
	add esp, 4
	pop ecx
	pop esi
	pop edi
	pop ebp
	ret
x86call ENDP

END 