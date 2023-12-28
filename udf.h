#pragma once
#include <ntstrsafe.h>

NTSTATUS ResizeUnicodeString(PUNICODE_STRING unicodeString, USHORT newMaxLength);
BOOLEAN SubstringInUnicodeString(PUNICODE_STRING mainString, PUNICODE_STRING substring);
BOOLEAN StartsWithUnicodeString(PUNICODE_STRING mainString, PUNICODE_STRING substring);
BOOLEAN EndsWithUnicodeString(PUNICODE_STRING mainString, PUNICODE_STRING substring);

BOOLEAN isExecutableExtension(PUNICODE_STRING fullname, PUNICODE_STRING executableExtension);
BOOLEAN isContainSubstr(PUNICODE_STRING fullname, PUNICODE_STRING allowedPath);

