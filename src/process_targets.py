"""Shared scope for live snapshots and historical Sysmon image loads."""
import ntpath
import os


CORE = set("system registry smss.exe csrss.exe wininit.exe winlogon.exe services.exe lsass.exe svchost.exe "
           "explorer.exe dwm.exe dllhost.exe rundll32.exe spoolsv.exe sihost.exe taskhostw.exe "
           "shellexperiencehost.exe startmenuexperiencehost.exe searchhost.exe fontdrvhost.exe "
           "msmpeng.exe nissrv.exe mssense.exe securityhealthservice.exe".split())


def system_process(name, image, extras=()):
    path = ntpath.normcase(ntpath.normpath(image or ""))
    root = ntpath.normcase(ntpath.normpath(os.environ.get("SystemRoot") or r"C:\Windows")).rstrip("\\")
    return (name.casefold() in CORE or name.casefold() in extras or path.startswith(root + "\\")
            or any(s in path for s in ("\\windowsapps\\microsoftwindows.", "\\windowsapps\\microsoft.windows.")))
