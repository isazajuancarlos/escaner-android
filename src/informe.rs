// SPDX-License-Identifier: MIT OR Apache-2.0
//! Render del informe (cruza la frontera a PANTALLA/archivo, directiva 28).
//! Puro: de datos a texto; el binario lo imprime o lo guarda.

use crate::modelo::{Hallazgo, Severidad};

/// Metadatos del escaneo para la cabecera del informe.
pub struct Cabecera {
    pub aparato: String,
    pub fecha: String,
}

/// Cuenta hallazgos por severidad: (crítica, alta, media, info).
#[must_use]
pub fn conteo(hallazgos: &[Hallazgo]) -> (usize, usize, usize, usize) {
    let mut c = (0, 0, 0, 0);
    for h in hallazgos {
        match h.severidad {
            Severidad::Critica => c.0 += 1,
            Severidad::Alta => c.1 += 1,
            Severidad::Media => c.2 += 1,
            Severidad::Info => c.3 += 1,
        }
    }
    c
}

/// Render completo del informe en texto plano.
#[must_use]
pub fn render(cab: &Cabecera, hallazgos: &[Hallazgo]) -> String {
    let (cr, al, me, inf) = conteo(hallazgos);
    let mut s = String::new();
    s.push_str("== ESCÁNER DE HIGIENE ANDROID ==\n");
    s.push_str(&format!("Aparato: {}\n", cab.aparato));
    s.push_str(&format!("Fecha:   {}\n", cab.fecha));
    s.push_str(&format!(
        "Resumen: {cr} crítica(s), {al} alta(s), {me} media(s), {inf} info\n",
    ));
    s.push('\n');

    if hallazgos.iter().all(|h| h.severidad == Severidad::Info) {
        s.push_str("Sin hallazgos de higiene por encima de INFO en lo cotejado.\n");
        s.push_str("RECUERDA: esto NO es un forense. Un aparato limpio aquí puede estar\n");
        s.push_str("comprometido por un implante privilegiado; para eso, MVT + Citizen Lab (§6).\n\n");
    }

    for h in hallazgos {
        s.push_str(&format!("[{}] {} — {}\n", h.severidad, h.categoria, h.que));
        s.push_str(&format!("    evidencia:  {}\n", h.evidencia));
        s.push_str(&format!("    qué hacer:  {}\n\n", h.recomendacion));
    }

    s.push_str("--- Integridad (cadena de custodia para el dictamen) ---\n");
    s.push_str("Guarda este informe y séllalo: `sha256sum informe.txt`.\n");
    s.push_str("El cotejo de IoC NO es exhaustivo (directiva 30): un 0 = 'ninguno de estos',\n");
    s.push_str("no 'limpio'. Ante sospecha real, MVT de Amnesty y Access Now.\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modelo::Hallazgo;

    #[test]
    fn conteo_y_render_reflejan_las_severidades() {
        let hs = vec![
            Hallazgo::nuevo(Severidad::Critica, "ioc-stalkerware", "x", "com.evil", "y"),
            Hallazgo::nuevo(Severidad::Media, "sideload", "z", "com.raro", "w"),
        ];
        assert_eq!(conteo(&hs), (1, 0, 1, 0));
        let cab = Cabecera { aparato: "Moto G35".into(), fecha: "2026-09-30".into() };
        let txt = render(&cab, &hs);
        // El caso rojo (crítico) DEBE aparecer en la pantalla renderizada.
        assert!(txt.contains("CRÍTICA"));
        assert!(txt.contains("com.evil"));
        assert!(txt.contains("1 crítica"));
    }
}
