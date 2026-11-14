// SPDX-License-Identifier: MIT OR Apache-2.0
//! Modelo de datos del informe: severidad y hallazgo.

use std::fmt;

/// Severidad de un hallazgo, ordenada de mayor a menor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severidad {
    /// Indicio de compromiso o de control remoto activo.
    Critica,
    /// Debilidad seria que un atacante usa de puerta (parche viejo, admin abusivo).
    Alta,
    /// Higiene deficiente que amplía la superficie.
    Media,
    /// Dato de contexto; no es en sí una debilidad.
    Info,
}

impl fmt::Display for Severidad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severidad::Critica => "CRÍTICA",
            Severidad::Alta => "ALTA",
            Severidad::Media => "MEDIA",
            Severidad::Info => "INFO",
        };
        f.write_str(s)
    }
}

/// Un hallazgo del escaneo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hallazgo {
    pub severidad: Severidad,
    /// Categoría corta, estable (para agrupar y para el dictamen).
    pub categoria: String,
    /// Qué se observó, en una frase.
    pub que: String,
    /// El artefacto concreto (paquete, componente, valor) que lo dispara.
    pub evidencia: String,
    /// Qué hacer al respecto.
    pub recomendacion: String,
}

impl Hallazgo {
    pub fn nuevo(
        severidad: Severidad,
        categoria: &str,
        que: &str,
        evidencia: &str,
        recomendacion: &str,
    ) -> Self {
        Hallazgo {
            severidad,
            categoria: categoria.to_string(),
            que: que.to_string(),
            evidencia: evidencia.to_string(),
            recomendacion: recomendacion.to_string(),
        }
    }
}

/// Un componente Android `paquete/servicio` (accesibilidad, listener, admin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Componente {
    pub paquete: String,
    pub servicio: String,
}

/// Un paquete instalado y quién lo instaló.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paquete {
    pub nombre: String,
    /// Instalador declarado por el sistema; `None` = desconocido/preinstalado.
    pub instalador: Option<String>,
}
