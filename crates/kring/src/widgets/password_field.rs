//! Masked single-line text field for passwords and secrets.

use eframe::egui;
use zeroize::Zeroizing;

/// Initial capacity of password buffers, so typing rarely reallocates (and leaves copies).
const PASSWORD_CAPACITY: usize = 256;
/// Id namespace of password fields.
const ID_NAMESPACE: &str = "kring-password";

/// Field holding the (current) password.
pub const FIELD_PASSWORD: &str = "password";
/// Field holding the password confirmation.
pub const FIELD_CONFIRM: &str = "confirm";
/// Field holding the old password.
pub const FIELD_OLD: &str = "old";
/// Field holding an item secret.
pub const FIELD_SECRET: &str = "secret";
/// Every field name, used to forget their editor state.
const ALL_FIELDS: [&str; 4] = [FIELD_PASSWORD, FIELD_CONFIRM, FIELD_OLD, FIELD_SECRET];

/// Creates an empty password buffer, zeroized on drop.
pub fn new_buffer() -> Zeroizing<String> {
    Zeroizing::new(String::with_capacity(PASSWORD_CAPACITY))
}

/// Returns the widget id of a password field.
fn _field_id(field: &str) -> egui::Id {
    egui::Id::unique((ID_NAMESPACE, field))
}

/// Shows a masked text field editing `buffer`.
pub fn password_field(
    ui: &mut egui::Ui,
    field: &str,
    buffer: &mut Zeroizing<String>,
    hint: &str,
) -> egui::Response {
    let text: &mut String = buffer;
    ui.add(
        egui::TextEdit::singleline(text)
            .id(_field_id(field))
            .password(true)
            .hint_text(hint),
    )
}

/// Drops the editor state (undo history holds copies of the text) of every password field.
pub fn forget_fields(ctx: &egui::Context) {
    ctx.data_mut(|d| {
        for field in ALL_FIELDS {
            d.remove::<egui::text_edit::TextEditState>(_field_id(field));
        }
    });
}
