//! Application bootstrap — main.rs'in 770 satırlık tanrı fonksiyonunu domain
//! bazlı modüllere bölmek için ilk adım. v3.0 audit Yarı C madde 26.
//!
//! Bu sürümde tek bir `AppState` struct + `AppState::init()` async fn topluyor
//! tüm Arc state'i. main.rs sadece CLI dispatch + HttpServer wire ediyor.
//! Domain-by-domain bootstrap (örn. `bootstrap::auth::init`, `bootstrap::
//! gateway::init`) v3.1.0 milestone'una bırakıldı — bu adım risk-azaltma ile
//! ~770 satır init'i tek dosyaya merge etti.

pub mod state;

pub use state::AppState;
