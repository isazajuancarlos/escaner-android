// SPDX-License-Identifier: MIT OR Apache-2.0
//! Parsers PUROS de la salida de ADB y clasificación en hallazgos.
//!
//! Cada función recibe TEXTO (la misma costura que usa el camino real, para que
//! el caso rojo falle por la vía real y no por el arnés — directiva 33) y no
//! toca el sistema. La E/S (llamar a `adb`) vive en el binario.

use std::collections::HashSet;

use crate::ioc;
use crate::modelo::{Componente, Hallazgo, Paquete, Severidad};

/// Instaladores considerados de confianza (no disparan sideload).
const INSTALADORES_CONFIABLES: &[&str] = &["com.android.vending"];

/// Umbrales de antigüedad del parche de seguridad, en meses.
const PARCHE_ALTA_MESES: i32 = 6;
const PARCHE_MEDIA_MESES: i32 = 3;

/// Materia prima del análisis: la salida cruda de cada comando ADB.
/// `None` = ese comando no se pudo recoger (se reporta como no verificado,
/// nunca se asume sano — directiva 20).
#[derive(Debug, Default, Clone)]
pub struct Entradas {
    pub paquetes: Option<String>,           // pm list packages -i
    pub paquetes_sistema: Option<String>,   // pm list packages -s (preinstaladas de fábrica)
    pub accesibilidad: Option<String>,      // settings get secure enabled_accessibility_services
    pub listeners: Option<String>,          // settings get secure enabled_notification_listeners
    pub admins: Option<String>,             // dumpsys device_policy
    pub parche: Option<String>,             // getprop ro.build.version.security_patch
    pub verified_boot: Option<String>,      // getprop ro.boot.verifiedbootstate
    pub debuggable: Option<String>,         // getprop ro.debuggable
    pub adb_enabled: Option<String>,        // settings get global adb_enabled
}

/// Parsea una lista de componentes `pkg/servicio` separada por `:`.
/// Formato de `enabled_accessibility_services` y `enabled_notification_listeners`.
#[must_use]
pub fn parsear_componentes(salida: &str) -> Vec<Componente> {
    let s = salida.trim();
    if s.is_empty() || s == "null" {
        return Vec::new();
    }
    s.split(':')
        .filter_map(|entrada| {
            let e = entrada.trim();
            if e.is_empty() {
                return None;
            }
            let (paquete, servicio) = e.split_once('/')?;
            Some(Componente {
                paquete: paquete.to_string(),
                servicio: servicio.to_string(),
            })
        })
        .collect()
}

/// Extrae los componentes `ComponentInfo{pkg/cls}` de un volcado (device admins).
#[must_use]
pub fn parsear_component_info(dumpsys: &str) -> Vec<Componente> {
    let mut fuera = Vec::new();
    let mut resto = dumpsys;
    while let Some(ini) = resto.find("ComponentInfo{") {
        let tras = &resto[ini + "ComponentInfo{".len()..];
        if let Some(fin) = tras.find('}') {
            let dentro = &tras[..fin];
            if let Some((p, c)) = dentro.split_once('/') {
                let comp = Componente {
                    paquete: p.trim().to_string(),
                    servicio: c.trim().to_string(),
                };
                if !fuera.contains(&comp) {
                    fuera.push(comp);
                }
            }
            resto = &tras[fin + 1..];
        } else {
            break;
        }
    }
    fuera
}

/// Parsea `pm list packages -i -u`: líneas `package:<nombre>  installer=<x>`.
#[must_use]
pub fn parsear_paquetes(salida: &str) -> Vec<Paquete> {
    salida
        .lines()
        .filter_map(|linea| {
            let l = linea.trim();
            let resto = l.strip_prefix("package:")?;
            let mut it = resto.split_whitespace();
            let nombre = it.next()?.to_string();
            let mut instalador = None;
            for tok in it {
                if let Some(v) = tok.strip_prefix("installer=") {
                    instalador = if v == "null" || v.is_empty() {
                        None
                    } else {
                        Some(v.to_string())
                    };
                }
            }
            Some(Paquete { nombre, instalador })
        })
        .collect()
}

/// Extrae el conjunto de nombres de paquete de una salida `package:<nombre>`
/// (formato de `pm list packages` y `pm list packages -s`).
#[must_use]
pub fn parsear_nombres(salida: &str) -> HashSet<String> {
    salida
        .lines()
        .filter_map(|l| {
            let resto = l.trim().strip_prefix("package:")?;
            resto.split_whitespace().next().map(str::to_string)
        })
        .collect()
}

/// ¿El instalador indica que la app se instaló por fuera de la tienda?
#[must_use]
pub fn es_sideload(instalador: &Option<String>) -> bool {
    match instalador {
        Some(x) => !INSTALADORES_CONFIABLES.contains(&x.as_str()),
        None => false, // desconocido/preinstalado: no se acusa (evita ruido, D23)
    }
}

/// Meses transcurridos desde la fecha de parche `YYYY-MM-DD` hasta `hoy`.
/// Devuelve `None` si no parsea. `hoy` = (año, mes).
#[must_use]
pub fn meses_desde_parche(getprop: &str, hoy: (i32, i32)) -> Option<i32> {
    let f = getprop.trim();
    let mut it = f.split('-');
    let y: i32 = it.next()?.parse().ok()?;
    let m: i32 = it.next()?.parse().ok()?;
    if !(1..=12).contains(&m) {
        return None;
    }
    let meses = (hoy.0 - y) * 12 + (hoy.1 - m);
    Some(meses.max(0))
}

/// Corre todo el análisis y devuelve los hallazgos ordenados por severidad.
#[must_use]
pub fn analizar(e: &Entradas, hoy: (i32, i32)) -> Vec<Hallazgo> {
    let mut h: Vec<Hallazgo> = Vec::new();

    // --- Paquetes: IoC de stalkerware + sideload vs bloatware preinstalado ---
    // El conjunto de apps de SISTEMA (partición de fábrica) distingue el
    // bloatware preinstalado de un sideload que hizo el usuario. Si no se pudo
    // recoger, se avisa y NO se asume (D20): todo no-Play cae a sideload (D21,
    // dirección segura).
    let sistema: HashSet<String> = e
        .paquetes_sistema
        .as_deref()
        .map(parsear_nombres)
        .unwrap_or_default();
    if e.paquetes_sistema.is_none() && e.paquetes.is_some() {
        h.push(no_verificado(
            "lista de apps de sistema (sideload vs preinstalado)",
            "pm list packages -s",
        ));
    }
    match &e.paquetes {
        Some(txt) => {
            for p in parsear_paquetes(txt) {
                if ioc::es_stalkerware_conocido(&p.nombre) {
                    h.push(Hallazgo::nuevo(
                        Severidad::Critica,
                        "ioc-stalkerware",
                        "Paquete con nombre de stalkerware/spyware de consumo conocido",
                        &p.nombre,
                        "Aislar el aparato SIN apagarlo, preservar evidencia y seguir la ruta forense (MVT/Access Now). No desinstalar antes del forense.",
                    ));
                } else if es_sideload(&p.instalador) {
                    let inst = p.instalador.clone().unwrap_or_default();
                    if sistema.contains(&p.nombre) {
                        h.push(Hallazgo::nuevo(
                            Severidad::Info,
                            "bloatware-preinstalado",
                            "App preinstalada de fábrica fuera de la tienda (no la instalaste tú)",
                            &format!("{} (installer={})", p.nombre, inst),
                            "Viene de fábrica. Si es un fastidio de privacidad (p. ej. Facebook), deshabilítala en Ajustes → Apps.",
                        ));
                    } else {
                        h.push(Hallazgo::nuevo(
                            Severidad::Media,
                            "sideload",
                            "App instalada por fuera de la tienda oficial",
                            &format!("{} (installer={})", p.nombre, inst),
                            "Verificar que la instalaste TÚ y confías en su origen; si no, desinstalar.",
                        ));
                    }
                }
            }
        }
        None => h.push(no_verificado("paquetes instalados", "pm list packages -i")),
    }

    // --- Accesibilidad: poder alto, vector típico de stalkerware ---
    revisar_componentes(
        &mut h,
        &e.accesibilidad,
        parsear_componentes,
        "accesibilidad",
        "Servicio de accesibilidad activo (puede leer pantalla y simular toques)",
        "settings get secure enabled_accessibility_services",
    );

    // --- Listeners de notificación: leen TODAS las notificaciones ---
    revisar_componentes(
        &mut h,
        &e.listeners,
        parsear_componentes,
        "listener-notificaciones",
        "App con acceso a leer todas las notificaciones",
        "settings get secure enabled_notification_listeners",
    );

    // --- Administradores de dispositivo: persistencia y control ---
    revisar_componentes(
        &mut h,
        &e.admins,
        parsear_component_info,
        "admin-dispositivo",
        "App con privilegios de administrador de dispositivo",
        "dumpsys device_policy",
    );

    // --- Nivel de parche ---
    match &e.parche {
        Some(txt) => match meses_desde_parche(txt, hoy) {
            Some(meses) if meses >= PARCHE_ALTA_MESES => h.push(Hallazgo::nuevo(
                Severidad::Alta,
                "parche-viejo",
                "Parche de seguridad muy atrasado",
                &format!("{} ({} meses)", txt.trim(), meses),
                "Buscar actualización del sistema; si el fabricante ya no la da, el aparato no es apto para datos sensibles.",
            )),
            Some(meses) if meses >= PARCHE_MEDIA_MESES => h.push(Hallazgo::nuevo(
                Severidad::Media,
                "parche-viejo",
                "Parche de seguridad atrasado",
                &format!("{} ({} meses)", txt.trim(), meses),
                "Aplicar la actualización del sistema pendiente.",
            )),
            Some(_) => {}
            None => h.push(no_verificado("nivel de parche", "getprop ro.build.version.security_patch")),
        },
        None => h.push(no_verificado("nivel de parche", "getprop ro.build.version.security_patch")),
    }

    // --- Arranque verificado / root ---
    if let Some(vb) = &e.verified_boot {
        let v = vb.trim();
        if !v.is_empty() && v != "green" {
            h.push(Hallazgo::nuevo(
                Severidad::Alta,
                "arranque-no-verificado",
                "El arranque verificado NO está en verde (bootloader desbloqueado o sistema alterado)",
                v,
                "En un aparato para datos sensibles, el bootloader debe estar bloqueado y el estado 'green'.",
            ));
        }
    }
    if e.debuggable.as_deref().map(str::trim) == Some("1") {
        h.push(Hallazgo::nuevo(
            Severidad::Alta,
            "build-debuggable",
            "El sistema es una compilación 'debuggable' (ro.debuggable=1)",
            "ro.debuggable=1",
            "Una ROM debuggable amplía mucho la superficie; no usarla para datos sensibles.",
        ));
    }

    // --- Depuración USB (informativo: está ON porque lo usamos ahora) ---
    if e.adb_enabled.as_deref().map(str::trim) == Some("1") {
        h.push(Hallazgo::nuevo(
            Severidad::Info,
            "depuracion-usb",
            "La depuración USB está activada",
            "adb_enabled=1",
            "Desactívala cuando termines el escaneo; déjala solo mientras la usas.",
        ));
    }

    h.sort_by_key(|a| a.severidad);
    h
}

/// Ayudante: parsea una entrada de componentes y clasifica cada uno,
/// escalando a CRÍTICA si el paquete es un IoC conocido.
fn revisar_componentes(
    h: &mut Vec<Hallazgo>,
    entrada: &Option<String>,
    parser: fn(&str) -> Vec<Componente>,
    categoria: &str,
    que: &str,
    comando: &str,
) {
    match entrada {
        Some(txt) => {
            for c in parser(txt) {
                let evidencia = format!("{}/{}", c.paquete, c.servicio);
                if ioc::es_stalkerware_conocido(&c.paquete) {
                    h.push(Hallazgo::nuevo(
                        Severidad::Critica,
                        "ioc-stalkerware",
                        "Stalkerware conocido con control activo sobre el aparato",
                        &evidencia,
                        "Indicio de compromiso. Preservar evidencia y ruta forense; no desinstalar antes.",
                    ));
                } else {
                    h.push(Hallazgo::nuevo(
                        Severidad::Media,
                        categoria,
                        que,
                        &evidencia,
                        "Revisar si reconoces esta app y si necesita este permiso; revocarlo si no.",
                    ));
                }
            }
        }
        None => h.push(no_verificado(categoria, comando)),
    }
}

fn no_verificado(que: &str, comando: &str) -> Hallazgo {
    Hallazgo::nuevo(
        Severidad::Info,
        "no-verificado",
        &format!("No se pudo recoger: {que} (no se asume sano)"),
        comando,
        "Reintentar la recolección; sin este dato el eje queda SIN VERIFICAR.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parsear_componentes: pareja rojo/verde ---
    #[test]
    fn componentes_rojo_y_verde() {
        // Rojo: dos servicios activos.
        let r = parsear_componentes("com.a.spy/.Svc:com.b/com.b.Watcher");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].paquete, "com.a.spy");
        assert_eq!(r[1].servicio, "com.b.Watcher");
        // Verde: vacío y "null" no producen componentes.
        assert!(parsear_componentes("").is_empty());
        assert!(parsear_componentes("null").is_empty());
    }

    // --- parsear_component_info: pareja ---
    #[test]
    fn component_info_rojo_y_verde() {
        let dump = "Enabled Device Admins:\n  admin=ComponentInfo{com.evil.app/.Admin}\n";
        let r = parsear_component_info(dump);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].paquete, "com.evil.app");
        // Verde: sin ComponentInfo no extrae nada.
        assert!(parsear_component_info("No active admins").is_empty());
    }

    // --- parsear_paquetes + sideload: pareja ---
    #[test]
    fn paquetes_y_sideload_rojo_y_verde() {
        let txt = "package:com.whatsapp installer=com.android.vending\n\
                   package:com.raro.apk installer=com.android.packageinstaller\n\
                   package:com.sistema installer=null\n";
        let ps = parsear_paquetes(txt);
        assert_eq!(ps.len(), 3);
        // Verde: de Play no es sideload.
        assert!(!es_sideload(&ps[0].instalador));
        // Rojo: instalado por el package installer (manual) SÍ.
        assert!(es_sideload(&ps[1].instalador));
        // Verde: instalador desconocido (system) no se acusa.
        assert!(!es_sideload(&ps[2].instalador));
    }

    // --- meses_desde_parche: pareja ---
    #[test]
    fn meses_de_parche_rojo_y_verde() {
        // Rojo: parche de hace ~15 meses.
        assert_eq!(meses_desde_parche("2025-06-05", (2026, 9)), Some(15));
        // Verde: al día (mismo mes) = 0.
        assert_eq!(meses_desde_parche("2026-09-01", (2026, 9)), Some(0));
        // Basura no parsea (se reporta no verificado, no 0).
        assert_eq!(meses_desde_parche("desconocido", (2026, 9)), None);
    }

    // --- analizar: el IoC en accesibilidad DEBE salir CRÍTICO (vía real) ---
    #[test]
    fn analizar_marca_ioc_critico_y_limpio_no() {
        let e = Entradas {
            accesibilidad: Some("com.thetruthspy.android/.Svc".to_string()),
            paquetes: Some(
                "package:com.thetruthspy.android installer=com.android.packageinstaller\n".to_string(),
            ),
            ..Default::default()
        };
        let h = analizar(&e, (2026, 9));
        assert!(
            h.iter().any(|x| x.severidad == Severidad::Critica && x.categoria == "ioc-stalkerware"),
            "un IoC en accesibilidad tiene que salir CRÍTICO"
        );

        // Verde (control): aparato limpio y al día no produce CRÍTICO ni ALTA.
        let limpio = Entradas {
            paquetes: Some("package:com.whatsapp installer=com.android.vending\n".to_string()),
            accesibilidad: Some("null".to_string()),
            listeners: Some("null".to_string()),
            admins: Some("No active admins".to_string()),
            parche: Some("2026-09-01".to_string()),
            verified_boot: Some("green".to_string()),
            debuggable: Some("0".to_string()),
            ..Default::default()
        };
        let hl = analizar(&limpio, (2026, 9));
        assert!(
            !hl.iter().any(|x| x.severidad <= Severidad::Alta),
            "un aparato limpio y al día no debe producir hallazgos ALTA/CRÍTICA, salieron: {hl:?}"
        );
    }

    // --- distingue bloatware preinstalado de sideload de usuario ---
    #[test]
    fn distingue_bloatware_de_sideload() {
        // Las dos apps tienen instalador NO-Play; solo se diferencian por ser
        // o no de sistema. Caso tomado del ZTE real (Facebook preinstalado).
        let paquetes = "package:com.facebook.system installer=com.facebook.system\n\
                        package:com.raro.apk installer=com.android.packageinstaller\n";
        let sistema = "package:com.facebook.system\n"; // solo facebook es de fábrica

        let e = Entradas {
            paquetes: Some(paquetes.to_string()),
            paquetes_sistema: Some(sistema.to_string()),
            ..Default::default()
        };
        let h = analizar(&e, (2026, 9));

        let fb = h.iter().find(|x| x.evidencia.contains("com.facebook.system")).unwrap();
        let raro = h.iter().find(|x| x.evidencia.contains("com.raro.apk")).unwrap();
        // Verde: el preinstalado baja a INFO/bloatware, no MEDIA/sideload.
        assert_eq!(fb.categoria, "bloatware-preinstalado");
        assert_eq!(fb.severidad, Severidad::Info);
        // Rojo: el sideload de usuario SÍ es MEDIA.
        assert_eq!(raro.categoria, "sideload");
        assert_eq!(raro.severidad, Severidad::Media);

        // Control D20: SIN la lista de sistema, el mismo facebook cae a sideload
        // (dirección segura) y se avisa que no se pudo distinguir.
        let sin_sistema = Entradas {
            paquetes: Some(paquetes.to_string()),
            paquetes_sistema: None,
            ..Default::default()
        };
        let h2 = analizar(&sin_sistema, (2026, 9));
        let fb2 = h2.iter().find(|x| x.evidencia.contains("com.facebook.system")).unwrap();
        assert_eq!(fb2.categoria, "sideload", "sin lista de sistema, no se asume preinstalado");
        assert!(h2.iter().any(|x| x.categoria == "no-verificado"));
    }
}
