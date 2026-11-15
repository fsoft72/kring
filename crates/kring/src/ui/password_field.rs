//! Masked single-line text field for passwords and secrets, with a show/hide
//! eye like Paranoid's `secret_input`.

use eframe::egui;
use zeroize::Zeroizing;

use crate::ui::glyphs::Ico;
use crate::ui::widgets::{ico_button, input};

/// Initial capacity of password buffers, so typing rarely reallocates (and leaves copies).
const PASSWORD_CAPACITY: usize = 256;
/// Id namespace of password fields.
const ID_NAMESPACE: &str = "kring-password";
/// Id suffix of the per-field "show" flag.
const SHOW_SUFFIX: &str = "show";
/// Room left for the eye button next to the field.
const EYE_ROOM: f32 = 36.0;

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

/// Shows a masked text field editing `buffer`, with an eye toggling the mask.
pub fn password_field(
    ui: &mut egui::Ui,
    field: &str,
    buffer: &mut Zeroizing<String>,
    hint: &str,
) -> egui::Response {
    let id = _field_id(field);
    let show_id = id.with(SHOW_SUFFIX);
    let mut show = ui.data(|d| d.get_temp::<bool>(show_id).unwrap_or(false));
    let resp = ui
        .horizontal(|ui| {
            let width = ui.available_width() - EYE_ROOM;
            let text: &mut String = buffer;
            let resp = ui.add(
                input(text)
                    .id(id)
                    .password(!show)
                    .hint_text(hint)
                    .desired_width(width),
            );
            let (ico, tip) = if show {
                (Ico::EyeOff, "Hide")
            } else {
                (Ico::Eye, "Show")
            };
            if ico_button(ui, ico, tip, None, false) {
                show = !show;
            }
            resp
        })
        .inner;
    ui.data_mut(|d| d.insert_temp(show_id, show));
    resp
}

/// Drops the editor state (undo history holds copies of the text) and the
/// show flag of every password field.
pub fn forget_fields(ctx: &egui::Context) {
    ctx.data_mut(|d| {
        for field in ALL_FIELDS {
            let id = _field_id(field);
            d.remove::<egui::text_edit::TextEditState>(id);
            d.remove::<bool>(id.with(SHOW_SUFFIX));
        }
    });
}
