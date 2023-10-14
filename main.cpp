#include <windows.h>
#include <stdio.h>
#include <AccCtrl.h>
#include <Aclapi.h>

BOOL TakeOwnershipAndDelete(LPCTSTR filename) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    // 获取进程标记
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    LookupPrivilegeValue(NULL, SE_TAKE_OWNERSHIP_NAME, &tkp.Privileges[0].Luid);
    LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &tkp.Privileges[1].Luid);
    tkp.PrivilegeCount = 2;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tkp.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

    // 获取TAKE_OWNERSHIP和RESTORE权限
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

    // 验证是否获取了必要的权限
    if (GetLastError() != ERROR_SUCCESS)
        return FALSE;

    // 获取文件句柄
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

    // 定义新的所有者
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    PSID everyone_sid;

    // 创建一个“所有用户”的SID
    if(!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone_sid))
        return FALSE;

    // 设置新所有者
    if (!SetSecurityInfo(hFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, everyone_sid, NULL, NULL, NULL))
        return FALSE;

    CloseHandle(hFile);

    // 尝试删除文件或文件夹
    DWORD attrs = GetFileAttributes(filename);
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return FALSE;

    BOOL result = FALSE;
    if (attrs & FILE_ATTRIBUTE_DIRECTORY)
        result = RemoveDirectory(filename); // 删除文件夹
    else
        result = DeleteFile(filename); // 删除文件

    if (!result)
        return FALSE;

    return TRUE;
}

int main() {
    LPCTSTR filename = TEXT("C:\\Users\\admin\\AppData\\Local\\D3DSCache");

    if (TakeOwnershipAndDelete(filename))
        wprintf(L"已删除: %s\n", filename);
    else
        wprintf(L"无法删除: %s\n", filename);

    return 0;
}