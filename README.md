# escaner-android

Security-hygiene scanner for Android devices over ADB (read-only, defensive). MIT OR Apache-2.0. Rust.

**English** · [Español](#español)

---

## The code is not hosted here

Since August 2026 the source of this project **is not hosted on GitHub**, and it is not distributed through any package registry.

This is not abandonment, not an incident, and there was no breach. It is a decision: through 2026 the package registries and code-hosting platforms were hit by sustained, chained supply-chain attacks — the Shai-Hulud worm, ChainDrop in August, malicious extensions that exfiltrated thousands of private repositories. For a security tool, hosting the source there stopped being a neutral decision.

**The licence has not changed and the code is still available to anyone who asks** — delivered with a signature and a checksum, at no cost, with no NDA, no restriction on what you publish about it, and no expiry. Request it at **xiliux.com**.

---

## What it does

`escaner-android` audits an Android device from a PC over ADB. It covers the **95% real-world** threat surface: stalkerware, abusive apps, sideloaded software, outdated security patches, and unverified boot.

| Category | Signal | Severity |
|---|---|---|
| `ioc-stalkerware` | known stalkerware package name (Echap list) | CRITICAL |
| `ioc-stalkerware` | stalkerware with active accessibility / device-admin / notification listener | CRITICAL |
| `old-patch` | security patch > 6 months / > 3 months old | HIGH / MEDIUM |
| `unverified-boot` | `ro.boot.verifiedbootstate` ≠ green | HIGH |
| `debuggable-build` | `ro.debuggable=1` | HIGH |
| `accessibility` / `notification-listener` / `device-admin` | active, flagged for review | MEDIUM |
| `sideload` | third-party app installed outside the store | MEDIUM |
| `preinstalled-bloatware` | factory system partition app outside Play | INFO |
| `usb-debugging` / `unverified` | context / data not collected (not assumed healthy) | INFO |

### Why ADB and not an installed app

Since Android 11, an installed app **cannot list the packages or permissions of other apps** (`QUERY_ALL_PACKAGES` is blocked on Play). The ADB `shell` user can (`dumpsys`, `pm`, `appops`). The scanner therefore runs **from a PC over ADB** — not as a sandboxed APK: more accurate and more capable.

### Honest limits

**This is not an antivirus and not a Pegasus detector.** A privileged state-level implant hides from any unprivileged tool; for that, use **MVT by Amnesty International** and reach out to Citizen Lab / Access Now.

**Zero findings means "none of the checked indicators were found" — not "clean".** The scanner covers common threats, not all threats. Use it as one layer of a threat-assessment workflow, not as a final verdict.

### Measured quality

9 tests (paired red/green per signal category) · `cargo clippy -D warnings` green · end-to-end test that launches the real binary against captured device data.

---

## Español

Escáner de **higiene de seguridad** para dispositivos Android por ADB (solo lectura, defensivo). MIT OR Apache-2.0. Rust.

---

## El código no se publica aquí

Desde agosto de 2026, el código de este proyecto **no se aloja en GitHub**, ni se distribuye por ningún registro de paquetes.

No es abandono ni un incidente: es una decisión. A lo largo de 2026 los registros de paquetes y las plataformas de código han sufrido ataques encadenados de cadena de suministro —Shai-Hulud, ChainDrop en agosto, extensiones maliciosas que se llevaron miles de repositorios privados—. Alojar aquí el código de una herramienta de seguridad dejó de ser una decisión neutra.

**La licencia no cambia y el código se entrega a quien lo pida**, con su firma y su suma de verificación, sin coste, sin NDA, sin restricción sobre lo que publique y sin caducidad. Solicítalo en **xiliux.com**.

---

## Qué hace

`escaner-android` audita un dispositivo Android desde el PC por ADB. Cubre el **95 % real** de las amenazas móviles: stalkerware, apps abusivas, software instalado fuera de la tienda (sideload), parches de seguridad viejos y arranque no verificado.

| Categoría | Señal | Severidad |
|---|---|---|
| `ioc-stalkerware` | nombre de paquete de stalkerware conocido (lista Echap) | CRÍTICA |
| `ioc-stalkerware` | stalkerware con accesibilidad / admin / listener activo | CRÍTICA |
| `parche-viejo` | parche de seguridad > 6 meses / > 3 meses | ALTA / MEDIA |
| `arranque-no-verificado` | `ro.boot.verifiedbootstate` ≠ green | ALTA |
| `build-debuggable` | `ro.debuggable=1` | ALTA |
| `accesibilidad` / `listener-notificaciones` / `admin-dispositivo` | activos, para revisión | MEDIA |
| `sideload` | app de terceros instalada fuera de la tienda | MEDIA |
| `bloatware-preinstalado` | app de la partición de sistema fuera de Play | INFO |
| `depuracion-usb` / `no-verificado` | contexto / dato no recogido (no se asume sano) | INFO |

### Por qué por ADB y no como app en el teléfono

Desde Android 11 una app instalada **no puede ver los paquetes ni los permisos de otras** (`QUERY_ALL_PACKAGES` vetado en Play). El usuario `shell` de ADB sí (`dumpsys`, `pm`, `appops`). Por eso el escáner corre **desde el PC por ADB**, no como APK sandboxeado: más honesto y más capaz.

### Límites honestos

**No es un antivirus ni un detector de Pegasus.** Un implante estatal privilegiado se esconde de cualquier herramienta sin privilegios. Para eso usa **MVT de Amnesty International** y contacta a Citizen Lab / Access Now.

**Cero hallazgos significa "ninguno de los indicadores cotejados fue encontrado" — no "limpio".** El escáner cubre amenazas comunes, no todas. Úsalo como una capa de un proceso de evaluación de amenazas, no como veredicto final.

### Calidad medida

9 pruebas (parejas rojo/verde por categoría de señal) · `cargo clippy -D warnings` verde · prueba de extremo a extremo contra el binario real.

---

*escaner-android* — © 2026 Juan Carlos Isaza. Licencia **MIT OR Apache-2.0**.
