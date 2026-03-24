---
title: "Auditoría Interna - Infraestructura CorpX"
date: 2026-03-24
draft: false
description: "Un ejemplo de informe profesional de Pentesting detallando hallazgos técnicos y resúmenes ejecutivos."
tags: ["Pentesting", "Reporte", "Red Externa", "SysReptor"]
categories: ["Informes Profesionales"]
---

{{< lead >}}
Documento descriptivo de los hallazgos tras la auditoría de caja negra sobre la infraestructura perimetral de CorpX.
{{< /lead >}}

## 📋 Resumen Ejecutivo

Durante los días **[Fechas]**, se llevó a cabo una auditoría de seguridad (Pentest) sobre la infraestructura de la empresa CorpX. El objetivo principal fue identificar, explotar y documentar vulnerabilidades en los sistemas expuestos a Internet.

Se lograron comprometer múltiples sistemas críticos debido a contraseñas débiles y servicios desactualizados. 

## 🎯 Alcance (Scope)

*   `192.168.1.0/24` (Red Corporativa Principal)
*   `*.corpx.local` (Dominio Interno)

## 🚨 Hallazgos y Vulnerabilidades

### 1. [Crítico] Ejecución Remota de Código (RCE) en Web Server Ppal
**CVSS V3 Score:** 9.8 (CRITICAL)

El servidor principal expone la versión vulnerable de Apache Struts. Mediante un payload diseñado específicamente, se logró obtener una shell interactiva como el usuario `www-data`, lo cual posteriormente permitió la elevación de privilegios.

**Recomendación:** Actualizar inmediatamente el componente a la versión más reciente.

### 2. [Alto] Misconfiguración en Active Directory (AS-REP Roasting)
**CVSS V3 Score:** 7.5 (HIGH)

Se encontraron múltiples cuentas sin la opción de preautenticación Kerberos habilitada. Esto permitió la recolección de hashes TGT que posteriormente fueron crackeados de manera offline.

```bash
Impacket-GetNPUsers corpx.local/ -usersfile users.txt -format hashcat -outputfile hashes.txt
```

**Recomendación:** Activar la política "Do not require Kerberos preauthentication" en todos los usuarios del dominio CorpX.

---

> *Nota: Este informe es un ejemplo metodológico para el portafolio y los resultados han sido anonimizados/ofuscados.*
