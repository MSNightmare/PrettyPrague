# PrettyPrague
GenDigital Avast Antivirus ZeroDay Elevation of Privileges Vulnerability

Another zeroday in an antimalware provider, I'm not sure but I believe this vulnerability affect other GenDigital products as well (such as AVG, Norton...)

For now the PoC is compatible with any version of Avast Antivirus.

The PoC will dump the SAM database by abusing a vulnerability in Avast Sandbox and spawn a full SYSTEM shell, at the time of writing this the PoC works with fully patched Avast Antivirus + Patched Windows 11 25H2

<img width="2008" height="953" alt="pl" src="https://github.com/user-attachments/assets/1099b082-749d-4dc5-af22-6a4d88810cd5" />
