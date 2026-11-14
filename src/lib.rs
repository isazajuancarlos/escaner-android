// SPDX-License-Identifier: MIT OR Apache-2.0
//! escaner-android — escáner de higiene de seguridad para Android, por ADB.
//!
//! Defensivo y propio: audita los aparatos de Juan (y de clientes del dictamen)
//! contra el 95% real —stalkerware, apps abusivas, sideload, parche viejo—.
//! NO detecta implantes estatales privilegiados; para eso, MVT + forense (§6).
//!
//! El núcleo (`analisis`) es PURO y se prueba contra texto; la E/S de `adb`
//! vive en el binario. Corre en vivo (`adb`) o contra volcados guardados
//! (offline/forense y para pruebas sin teléfono).

pub mod analisis;
pub mod informe;
pub mod ioc;
pub mod modelo;
