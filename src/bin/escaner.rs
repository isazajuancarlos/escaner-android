// SPDX-License-Identifier: MIT OR Apache-2.0
//! Binario `escaner-android`: recoge por ADB (o lee volcados) y emite el informe.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use escaner_android::analisis::{analizar, Entradas};
use escaner_android::informe::{render, Cabecera};

#[derive(Parser, Debug)]
#[command(
    name = "escaner-android",
    about = "Escáner de higiene de seguridad para Android por ADB (defensivo, propio)."
)]
struct Args {
    /// Serial del dispositivo (adb -s), si hay varios conectados.
    #[arg(short, long)]
    serial: Option<String>,
    /// Leer los volcados desde un directorio en vez de correr adb (offline).
    #[arg(long)]
    desde: Option<PathBuf>,
    /// Guardar los volcados crudos en un directorio (cadena de custodia / pruebas).
    #[arg(long)]
    guardar: Option<PathBuf>,
    /// Fecha de hoy YYYY-MM (para el cálculo del parche). Por defecto: la del sistema.
    #[arg(long)]
    hoy: Option<String>,
}

/// Los ejes que se recogen: (nombre de archivo, argumentos de `adb shell`).
const EJES: &[(&str, &[&str])] = &[
    ("modelo", &["getprop", "ro.product.model"]),
    ("paquetes", &["pm", "list", "packages", "-i"]),
    ("paquetes_sistema", &["pm", "list", "packages", "-s"]),
    ("accesibilidad", &["settings", "get", "secure", "enabled_accessibility_services"]),
    ("listeners", &["settings", "get", "secure", "enabled_notification_listeners"]),
    ("admins", &["dumpsys", "device_policy"]),
    ("parche", &["getprop", "ro.build.version.security_patch"]),
    ("verified_boot", &["getprop", "ro.boot.verifiedbootstate"]),
    ("debuggable", &["getprop", "ro.debuggable"]),
    ("adb_enabled", &["settings", "get", "global", "adb_enabled"]),
];

fn adb_shell(serial: &Option<String>, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new("adb");
    if let Some(s) = serial {
        cmd.arg("-s").arg(s);
    }
    cmd.arg("shell").args(args);
    let salida = cmd.output().ok()?;
    if !salida.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&salida.stdout).into_owned())
}

fn fecha_hoy() -> String {
    Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "fecha-desconocida".to_string())
}

fn recoger_vivo(serial: &Option<String>) -> Vec<(String, Option<String>)> {
    EJES.iter()
        .map(|(nombre, args)| ((*nombre).to_string(), adb_shell(serial, args)))
        .collect()
}

fn recoger_desde(dir: &Path) -> Vec<(String, Option<String>)> {
    EJES.iter()
        .map(|(nombre, _)| {
            let ruta = dir.join(format!("{nombre}.txt"));
            (nombre.to_string(), fs::read_to_string(&ruta).ok())
        })
        .collect()
}

fn valor(crudos: &[(String, Option<String>)], nombre: &str) -> Option<String> {
    crudos
        .iter()
        .find(|(n, _)| n == nombre)
        .and_then(|(_, v)| v.clone())
}

fn main() {
    let args = Args::parse();

    // 1. Recoger.
    let crudos = match &args.desde {
        Some(dir) => recoger_desde(dir),
        None => {
            if adb_shell(&args.serial, &["true"]).is_none() {
                eprintln!(
                    "No se pudo hablar con el dispositivo por adb.\n\
                     - Instala adb en el PC:  sudo apt install adb\n\
                     - En el teléfono: Ajustes → Acerca del teléfono → tocar 7 veces\n\
                       'Número de compilación' → Opciones de desarrollador → Depuración USB.\n\
                     - Conéctalo por USB y acepta la huella; comprueba con `adb devices`.\n\
                     (O corre offline contra volcados con --desde <dir>.)"
                );
                std::process::exit(2);
            }
            recoger_vivo(&args.serial)
        }
    };

    // 2. Guardar crudos si se pidió.
    if let Some(dir) = &args.guardar {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("No se pudo crear {}: {e}", dir.display());
        } else {
            for (nombre, val) in &crudos {
                if let Some(v) = val {
                    let _ = fs::write(dir.join(format!("{nombre}.txt")), v);
                }
            }
        }
    }

    // 3. Armar entradas.
    let e = Entradas {
        paquetes: valor(&crudos, "paquetes"),
        paquetes_sistema: valor(&crudos, "paquetes_sistema"),
        accesibilidad: valor(&crudos, "accesibilidad"),
        listeners: valor(&crudos, "listeners"),
        admins: valor(&crudos, "admins"),
        parche: valor(&crudos, "parche"),
        verified_boot: valor(&crudos, "verified_boot"),
        debuggable: valor(&crudos, "debuggable"),
        adb_enabled: valor(&crudos, "adb_enabled"),
    };

    // 4. Fecha para el cálculo del parche.
    let fecha = args.hoy.unwrap_or_else(fecha_hoy);
    let hoy = parsear_ym(&fecha).unwrap_or((1970, 1));

    // 5. Analizar y renderizar.
    let hallazgos = analizar(&e, hoy);
    let aparato = valor(&crudos, "modelo")
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "desconocido".to_string());
    let cab = Cabecera { aparato, fecha };
    print!("{}", render(&cab, &hallazgos));
}

/// Extrae (año, mes) de una fecha "YYYY-MM-DD" o "YYYY-MM".
fn parsear_ym(fecha: &str) -> Option<(i32, i32)> {
    let mut it = fecha.trim().split('-');
    let y: i32 = it.next()?.parse().ok()?;
    let m: i32 = it.next()?.parse().ok()?;
    Some((y, m))
}
