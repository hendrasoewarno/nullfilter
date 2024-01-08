#pragma once
#include <ntstrsafe.h>

NTSTATUS ReadRegistryValueFromMiniFilter(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PWCHAR ValueName,
    _Out_ PUNICODE_STRING Value
);

NTSTATUS ResizeUnicodeString(PUNICODE_STRING unicodeString, USHORT newMaxLength);
BOOLEAN SubstringInUnicodeString(PUNICODE_STRING mainString, PUNICODE_STRING substring);
BOOLEAN StartsWithUnicodeString(PUNICODE_STRING mainString, PUNICODE_STRING substring);
BOOLEAN EndsWithUnicodeString(PUNICODE_STRING mainString, PUNICODE_STRING substring);

BOOLEAN isEndsWith(PUNICODE_STRING fullname, PUNICODE_STRING executableExtension);
BOOLEAN isContainSubstr(PUNICODE_STRING fullname, PUNICODE_STRING allowedPath);

