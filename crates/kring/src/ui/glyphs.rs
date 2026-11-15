//! Vector line icons drawn with the egui painter (no emoji, no font
//! dependency): crisp at any scale and recoloured by state. Same 16-unit grid
//! and 1.6 px line style as Paranoid's `glyphs.rs`.

use eframe::egui::{self, Color32, CornerRadius, Painter, Pos2, Rect, Stroke, StrokeKind, pos2};

/// Width of icon lines.
const LINE_WIDTH: f32 = 1.6;
/// Share of the smaller side of the target rect used by the icon box.
const ICON_SCALE: f32 = 0.6;
/// Points of curves (eye lids, arcs).
const CURVE_STEPS: usize = 12;

/// Icons available to the UI.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ico {
    /// Show a secret.
    Eye,
    /// Hide a secret.
    EyeOff,
    /// Copy to the clipboard.
    Copy,
    /// Close or clear.
    Close,
    /// Key (Secrets area, change password).
    Key,
    /// Closed padlock (lock, locked state).
    Lock,
    /// Open padlock (unlock).
    Unlock,
    /// Magnifier of search boxes.
    Search,
    /// Set as default.
    Star,
    /// Rename or edit.
    Pencil,
    /// Delete.
    Trash,
    /// Add.
    Plus,
    /// Collapsed card.
    ChevronRight,
    /// Expanded card.
    ChevronDown,
    /// Offline files area.
    Folder,
    /// KWallet area.
    Wallet,
    /// SSH keys area.
    Terminal,
    /// GPG keys area.
    Shield,
    /// Tools area.
    Sliders,
}

/// Maps 16-unit grid coordinates to screen positions inside an icon box.
struct Grid {
    center: Pos2,
    unit: f32,
}

impl Grid {
    /// Screen position of grid point (x, y).
    fn pt(&self, x: f32, y: f32) -> Pos2 {
        pos2(
            self.center.x + (x - 8.0) * self.unit,
            self.center.y + (y - 8.0) * self.unit,
        )
    }

    /// Points of an elliptic arc around (cx, cy) from angle `a0` to `a1` (radians).
    fn arc(&self, c: (f32, f32), r: (f32, f32), a0: f32, a1: f32) -> Vec<Pos2> {
        (0..=CURVE_STEPS)
            .map(|i| {
                let a = a0 + (a1 - a0) * i as f32 / CURVE_STEPS as f32;
                self.pt(c.0 + r.0 * a.cos(), c.1 + r.1 * a.sin())
            })
            .collect()
    }
}

/// Draws `ico` centred in `rect` (the icon box is 60% of the smaller side).
pub fn paint(p: &Painter, rect: Rect, ico: Ico, color: Color32) {
    let size = rect.width().min(rect.height()) * ICON_SCALE;
    let g = Grid {
        center: rect.center(),
        unit: size / 16.0,
    };
    let st = Stroke::new(LINE_WIDTH, color);
    match ico {
        Ico::Eye | Ico::EyeOff => _eye(p, &g, st, ico == Ico::EyeOff),
        Ico::Lock | Ico::Unlock => _lock(p, &g, st, ico == Ico::Unlock),
        Ico::Star => _star(p, &g, st),
        Ico::Trash => _trash(p, &g, st),
        Ico::ChevronRight => _poly(
            p,
            vec![g.pt(6.0, 3.5), g.pt(10.5, 8.0), g.pt(6.0, 12.5)],
            st,
        ),
        Ico::ChevronDown => _poly(
            p,
            vec![g.pt(3.5, 6.0), g.pt(8.0, 10.5), g.pt(12.5, 6.0)],
            st,
        ),
        _ => _simple(p, &g, st, ico),
    }
}

/// Draws an open polyline.
fn _poly(p: &Painter, pts: Vec<Pos2>, st: Stroke) {
    p.add(egui::Shape::line(pts, st));
}

/// Draws a rounded rectangle outline between two grid points.
fn _square(p: &Painter, g: &Grid, a: (f32, f32), b: (f32, f32), st: Stroke) {
    p.rect_stroke(
        Rect::from_two_pos(g.pt(a.0, a.1), g.pt(b.0, b.1)),
        CornerRadius::same(1),
        st,
        StrokeKind::Middle,
    );
}

/// Icons made of lines, rectangles and circles only.
fn _simple(p: &Painter, g: &Grid, st: Stroke, ico: Ico) {
    let line = |a: Pos2, b: Pos2| {
        p.line_segment([a, b], st);
    };
    match ico {
        Ico::Copy => {
            _square(p, g, (5.0, 5.0), (14.0, 14.0), st);
            _poly(
                p,
                vec![g.pt(3.0, 10.5), g.pt(3.0, 2.0), g.pt(10.5, 2.0)],
                st,
            );
        }
        Ico::Close => {
            line(g.pt(3.5, 3.5), g.pt(12.5, 12.5));
            line(g.pt(12.5, 3.5), g.pt(3.5, 12.5));
        }
        Ico::Key => {
            p.circle_stroke(g.pt(5.0, 8.0), 3.4 * g.unit, st);
            line(g.pt(8.4, 8.0), g.pt(14.5, 8.0));
            line(g.pt(12.0, 8.0), g.pt(12.0, 11.0));
            line(g.pt(14.5, 8.0), g.pt(14.5, 10.5));
        }
        Ico::Search => {
            p.circle_stroke(g.pt(7.0, 7.0), 4.3 * g.unit, st);
            line(g.pt(10.2, 10.2), g.pt(14.0, 14.0));
        }
        Ico::Pencil => {
            let body = vec![
                g.pt(10.5, 2.5),
                g.pt(13.5, 5.5),
                g.pt(5.5, 13.5),
                g.pt(2.5, 13.5),
                g.pt(2.5, 10.5),
                g.pt(10.5, 2.5),
            ];
            _poly(p, body, st);
            line(g.pt(9.0, 4.0), g.pt(12.0, 7.0));
        }
        Ico::Plus => {
            line(g.pt(8.0, 2.5), g.pt(8.0, 13.5));
            line(g.pt(2.5, 8.0), g.pt(13.5, 8.0));
        }
        Ico::Folder => {
            let outline = vec![
                g.pt(2.0, 4.0),
                g.pt(6.5, 4.0),
                g.pt(8.0, 5.5),
                g.pt(14.0, 5.5),
                g.pt(14.0, 13.0),
                g.pt(2.0, 13.0),
                g.pt(2.0, 4.0),
            ];
            _poly(p, outline, st);
        }
        Ico::Wallet => {
            _square(p, g, (2.0, 4.5), (14.0, 13.5), st);
            _square(p, g, (9.5, 7.5), (14.0, 10.5), st);
            p.circle_filled(g.pt(11.5, 9.0), 0.8 * g.unit, st.color);
        }
        Ico::Terminal => {
            _square(p, g, (1.5, 2.5), (14.5, 13.5), st);
            _poly(p, vec![g.pt(4.5, 6.0), g.pt(7.0, 8.0), g.pt(4.5, 10.0)], st);
            line(g.pt(8.5, 10.5), g.pt(11.5, 10.5));
        }
        Ico::Shield => {
            let outline = vec![
                g.pt(8.0, 1.5),
                g.pt(13.5, 3.5),
                g.pt(13.0, 9.0),
                g.pt(8.0, 14.5),
                g.pt(3.0, 9.0),
                g.pt(2.5, 3.5),
                g.pt(8.0, 1.5),
            ];
            _poly(p, outline, st);
            _poly(p, vec![g.pt(5.5, 8.0), g.pt(7.3, 9.8), g.pt(10.8, 6.2)], st);
        }
        Ico::Sliders => {
            for (y, k) in [(4.0, 10.0), (8.0, 5.0), (12.0, 11.0)] {
                line(g.pt(2.0, y), g.pt(14.0, y));
                p.rect_filled(
                    Rect::from_center_size(g.pt(k, y), egui::vec2(3.2 * g.unit, 3.2 * g.unit)),
                    CornerRadius::same(1),
                    st.color,
                );
            }
        }
        _ => {}
    }
}

/// Eye (optionally crossed out): two lids and the pupil.
fn _eye(p: &Painter, g: &Grid, st: Stroke, crossed: bool) {
    for sign in [-1.0_f32, 1.0] {
        let lid = (0..=CURVE_STEPS)
            .map(|i| {
                let t = i as f32 / CURVE_STEPS as f32;
                let y = 8.0 + sign * 5.5 * (1.0 - (2.0 * t - 1.0).powi(2));
                g.pt(1.0 + 14.0 * t, y)
            })
            .collect();
        _poly(p, lid, st);
    }
    p.circle_stroke(g.pt(8.0, 8.0), 2.2 * g.unit, st);
    if crossed {
        let bold = Stroke::new(1.8_f32, st.color);
        p.line_segment([g.pt(2.5, 13.5), g.pt(13.5, 2.5)], bold);
    }
}

/// Padlock; the open variant lifts the shackle off its right post.
fn _lock(p: &Painter, g: &Grid, st: Stroke, open: bool) {
    _square(p, g, (3.0, 7.0), (13.0, 14.0), st);
    let pi = std::f32::consts::PI;
    let (cx, lift) = if open { (10.0, 2.0) } else { (8.0, 0.0) };
    let mut shackle = g.arc((cx, 7.0 - lift), (3.0, 3.6), pi, 2.0 * pi);
    if open {
        shackle.insert(0, g.pt(cx - 3.0, 7.0));
    }
    _poly(p, shackle, st);
    p.circle_filled(g.pt(8.0, 10.5), 1.1 * g.unit, st.color);
}

/// Five-pointed star outline.
fn _star(p: &Painter, g: &Grid, st: Stroke) {
    let pi = std::f32::consts::PI;
    let pts: Vec<Pos2> = (0..=10)
        .map(|i| {
            let r = if i % 2 == 0 { 6.5 } else { 2.8 };
            let a = -pi / 2.0 + i as f32 * pi / 5.0;
            g.pt(8.0 + r * a.cos(), 8.5 + r * a.sin())
        })
        .collect();
    _poly(p, pts, st);
}

/// Trash can: lid, handle, body and two ribs.
fn _trash(p: &Painter, g: &Grid, st: Stroke) {
    p.line_segment([g.pt(2.0, 4.0), g.pt(14.0, 4.0)], st);
    _poly(
        p,
        vec![
            g.pt(6.0, 4.0),
            g.pt(6.5, 2.0),
            g.pt(9.5, 2.0),
            g.pt(10.0, 4.0),
        ],
        st,
    );
    let body = vec![
        g.pt(3.5, 4.0),
        g.pt(4.5, 14.0),
        g.pt(11.5, 14.0),
        g.pt(12.5, 4.0),
    ];
    _poly(p, body, st);
    for x in [6.8, 9.2] {
        p.line_segment([g.pt(x, 6.5), g.pt(x, 11.5)], st);
    }
}
