// SPDX-License-Identifier: MIT OR Apache-2.0
//! E2E: arranca el BINARIO real contra un volcado guardado y lee su informe
//! (directiva 28: cruzar la frontera del programa, no de estructura a estructura).

use std::process::Command;

fn correr(desde: &str) -> String {
    let bin = env!("CARGO_BIN_EXE_escaner-android");
    let salida = Command::new(bin)
        .args(["--desde", desde, "--hoy", "2026-09-30"])
        .output()
        .expect("no se pudo arrancar el binario");
    assert!(salida.status.success(), "el binario salió con error");
    String::from_utf8_lossy(&salida.stdout).into_owned()
}

#[test]
fn e2e_volcado_sucio_dibuja_lo_critico() {
    let out = correr("tests/fixtures/sucio");
    // Rojo: el IoC con control activo TIENE que salir crítico en pantalla.
    assert!(out.contains("2 crítica"), "faltan las críticas:\n{out}");
    assert!(out.contains("com.thetruthspy.android/.MonitorService"));
    assert!(out.contains("18 meses"), "no detectó el parche viejo:\n{out}");
}

#[test]
fn e2e_volcado_limpio_no_alarma() {
    let out = correr("tests/fixtures/limpio");
    // Verde (control): 0 críticas y 0 altas en un aparato al día.
    assert!(out.contains("0 crítica(s), 0 alta(s)"), "alarmó en limpio:\n{out}");
}
