#include <windows.h>
#include <stdio.h>
#include <AccCtrl.h>
#include <Aclapi.h>

BOOL TakeOwnershipAndDelete(LPCTSTR filename) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    // ��ȡ���̱��
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    LookupPrivilegeValue(NULL, SE_TAKE_OWNERSHIP_NAME, &tkp.Privileges[0].Luid);
    LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &tkp.Privileges[1].Luid);
    tkp.PrivilegeCount = 2;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tkp.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

    // ��ȡTAKE_OWNERSHIP��RESTOREȨ��
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

    // ��֤�Ƿ��ȡ�˱�Ҫ��Ȩ��
    if (GetLastError() != ERROR_SUCCESS)
        return FALSE;

    // ��ȡ�ļ����
    HANDLE hFile = CreateFile(
            filename,
            DELETE | WRITE_OWNER | WRITE_DAC,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
            NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    // �����µ�������
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    PSID everyone_sid;

    // ����һ���������û�����SID
    if(!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone_sid))
        return FALSE;

    // ������������
    if (!SetSecurityInfo(hFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, everyone_sid, NULL, NULL, NULL))
        return FALSE;

    CloseHandle(hFile);

    // ����ɾ���ļ����ļ���
    DWORD attrs = GetFileAttributes(filename);
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return FALSE;

    BOOL result = FALSE;
    if (attrs & FILE_ATTRIBUTE_DIRECTORY)
        result = RemoveDirectory(filename); // ɾ���ļ���
    else
        result = DeleteFile(filename); // ɾ���ļ�

    if (!result)
        return FALSE;

    return TRUE;
}

int main() {
    LPCTSTR filename = TEXT("C:\\Users\\admin\\AppData\\Local\\D3DSCache");

    if (TakeOwnershipAndDelete(filename))
        wprintf(L"��ɾ��: %s\n", filename);
    else
        wprintf(L"�޷�ɾ��: %s\n", filename);

    return 0;
}