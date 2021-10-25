# SeManageVolumeAbuse

Get full control over C:\ when the user has SeManageVolumePrivilege (allowing to read/write any files). One possible way to get a shell from here is to write a custom dll to C:\Windows\System32\wbem\tzres.dll & call systeminfo to trigger it.