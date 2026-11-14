// SPDX-License-Identifier: MIT OR Apache-2.0
//! Indicadores de compromiso: nombres de paquete de stalkerware conocido.
//!
//! Lista curada a partir del corpus público de indicadores de stalkerware de
//! Echap / Coalition Against Stalkerware (`stalkerware-indicators`). NO es
//! exhaustiva ni sustituye a MVT de Amnesty (el forense de verdad, §6 del
//! dictamen): es un cotejo de higiene rápido contra los nombres más vistos.
//!
//! LÍMITE (dicho para no engañar): el stalkerware se renombra y se esconde;
//! una lista de nombres caza al descuidado, no al implante privilegiado. Un
//! `0` aquí NO significa "limpio" (directiva 30) — significa "ninguno de ESTOS".
//! Actualizar contra la fuente al usar en un caso real.

/// Nombres de paquete asociados a stalkerware/spyware de consumo conocido.
pub const PAQUETES_STALKERWARE: &[&str] = &[
    "com.actualreports.mobile",
    "com.android.protender",
    "com.cellspy.android",
    "com.flexispy.android",
    "com.hellospy.system",
    "com.host.system",
    "com.mspy.lite",
    "com.mxpcs.hidden",
    "com.reptech.mobilespy",
    "com.spapp.messenger.hidden",
    "com.spy.phone.tracker",
    "com.spyhide.app",
    "com.spyzie.android",
    "com.system.service.hidden",
    "com.thetruthspy.android",
    "net.cospy.android",
    "system.android.service",
];

/// ¿El nombre de paquete está en la lista de IoC?
#[must_use]
pub fn es_stalkerware_conocido(paquete: &str) -> bool {
    PAQUETES_STALKERWARE.contains(&paquete)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn casa_un_ioc_y_no_una_app_normal() {
        // Rojo: un nombre de la lista.
        assert!(es_stalkerware_conocido("com.thetruthspy.android"));
        // Verde: una app legítima cualquiera.
        assert!(!es_stalkerware_conocido("com.whatsapp"));
        assert!(!es_stalkerware_conocido("org.mozilla.firefox"));
    }
}
