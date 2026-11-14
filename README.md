<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# escaner-android

Escáner de **higiene de seguridad** para Android, por ADB. Defensivo y propio:
audita los aparatos de Juan (y de clientes del dictamen de amenaza spyware) contra
el **95 % real** de amenazas —stalkerware, apps abusivas, sideload, parche viejo—.

## Qué NO es (léelo primero, directiva 30)

**No es un antivirus ni un detector de Pegasus.** Un implante estatal privilegiado
se esconde de cualquier herramienta sin privilegios; para ESO está **MVT de
Amnesty** (el forense de verdad) y Citizen Lab / Access Now. Un informe sin
hallazgos aquí significa *"ninguno de los indicadores cotejados"*, **no "limpio"**.

## Por qué por ADB y no como app en el teléfono

Desde Android 11 una app instalada **no puede ver los paquetes ni los permisos de
otras apps** (restricción de *package visibility*; `QUERY_ALL_PACKAGES` vetado en
Play). El usuario `shell` de ADB sí (`dumpsys`, `pm`, `appops`). Por eso el escáner
correcto corre **desde el PC por ADB**, no como APK sandboxeado: más honesto y más
capaz.

## Qué mira

| Categoría | Señal | Severidad |
|---|---|---|
| `ioc-stalkerware` | nombre de paquete de stalkerware conocido (lista Echap) | CRÍTICA |
| `ioc-stalkerware` | ese paquete con accesibilidad/admin/listener (control activo) | CRÍTICA |
| `parche-viejo` | `ro.build.version.security_patch` > 6 / > 3 meses | ALTA / MEDIA |
| `arranque-no-verificado` | `ro.boot.verifiedbootstate` ≠ green | ALTA |
| `build-debuggable` | `ro.debuggable=1` | ALTA |
| `accesibilidad` / `listener-notificaciones` / `admin-dispositivo` | activos, para revisión | MEDIA |
| `sideload` | app third-party instalada por fuera de la tienda (la instaló el usuario) | MEDIA |
| `bloatware-preinstalado` | app de sistema (partición de fábrica) fuera de Play — no la instaló el usuario | INFO |
| `depuracion-usb` / `no-verificado` | contexto / dato no recogido (no se asume sano) | INFO |

La distinción **sideload vs bloatware** usa `pm list packages -s` (apps de
sistema): una app con instalador no‑Play que además es de sistema es bloatware
de fábrica (INFO), no un sideload del usuario (MEDIA). Si no se pudo recoger la
lista de sistema, todo no‑Play cae a `sideload` (dirección segura, D20/D21) y se
avisa con `no-verificado`.

## Uso

Requiere `adb` en el PC (`sudo apt install adb`) y **Depuración USB** en el teléfono
(Ajustes → Acerca del teléfono → tocar 7× "Número de compilación" → Opciones de
desarrollador → Depuración USB). Comprueba con `adb devices`.

```bash
# En vivo, con el teléfono conectado:
cargo run --bin escaner-android

# Guardando los volcados crudos (cadena de custodia para el dictamen):
cargo run --bin escaner-android -- --guardar ./volcado-$(date +%F)

# Offline, contra volcados ya guardados (forense / sin teléfono):
cargo run --bin escaner-android -- --desde ./volcado-2026-09-30

# Varios dispositivos: -s <serial>
```

Sella el informe para la cadena de custodia: `escaner-android > informe.txt && sha256sum informe.txt`.

## Diseño

- Núcleo (`analisis`, `ioc`, `informe`, `modelo`) **puro**: de texto a hallazgos,
  probado con parejas rojo/verde (directiva 33) y un E2E que arranca el binario
  real (directiva 28).
- La E/S de `adb` vive solo en `src/bin/escaner.rs`.
- `cargo test` (9 pruebas) + `cargo clippy -- -D warnings` (verde).

## Límites y pendientes

- La lista de IoC es un cotejo rápido, **no exhaustiva**; actualizar contra la
  fuente pública (Echap / Coalition Against Stalkerware) al usar en un caso real.
- Los admins de dispositivo de Google (Find My Device) salen como MEDIA "para
  revisión": es ruido leve aceptable; una lista blanca de admins de sistema
  conocidos lo bajaría a INFO (pendiente).
- La distinción sideload vs bloatware preinstalado ya está hecha (2026-09-30,
  validada contra el ZTE real: los stubs de Facebook de fábrica bajan a INFO).
- El complemento forense es **MVT** por ADB/backup, encima de este escáner.

Titularidad: Isaza Arenas (Xiliux). MIT OR Apache-2.0.
