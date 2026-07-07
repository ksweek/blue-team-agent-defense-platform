from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "output" / "imagegen" / "guardianagent-admin-control-plane.png"
OUTPUT = ROOT / "output" / "imagegen" / "guardianagent-client-runtime-template-match.png"

NAVY = "#08245f"
BLUE = "#075ad7"
WHITE = "#ffffff"
CYAN = "#16bfe2"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = [
        Path("C:/Windows/Fonts/msyhbd.ttc") if bold else Path("C:/Windows/Fonts/msyh.ttc"),
        Path("C:/Windows/Fonts/simhei.ttf"),
        Path("C:/Windows/Fonts/arial.ttf"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size=size)
    return ImageFont.load_default()


def text_size(draw: ImageDraw.ImageDraw, text: str, fnt: ImageFont.ImageFont) -> tuple[int, int]:
    box = draw.textbbox((0, 0), text, font=fnt)
    return box[2] - box[0], box[3] - box[1]


def centered_text(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    lines: list[str],
    sizes: list[int],
    fills: list[str] | None = None,
    bolds: list[bool] | None = None,
    line_gap: int = 8,
) -> None:
    fills = fills or [NAVY] * len(lines)
    bolds = bolds or [False] * len(lines)
    fonts = [font(size, bold=bold) for size, bold in zip(sizes, bolds)]
    heights = [text_size(draw, line, fnt)[1] for line, fnt in zip(lines, fonts)]
    total_height = sum(heights) + line_gap * (len(lines) - 1)
    x1, y1, x2, y2 = box
    y = y1 + ((y2 - y1) - total_height) / 2
    for line, fnt, fill, height in zip(lines, fonts, fills, heights):
        width, _ = text_size(draw, line, fnt)
        draw.text((x1 + ((x2 - x1) - width) / 2, y), line, font=fnt, fill=fill)
        y += height + line_gap


def left_icon_monitor(draw: ImageDraw.ImageDraw) -> None:
    x, y = 674, 358
    draw.rounded_rectangle((x, y, x + 67, y + 55), radius=6, outline="#8ed6ff", width=4)
    draw.rectangle((x + 22, y + 55, x + 45, y + 65), fill="#8ed6ff")
    draw.rounded_rectangle((x + 14, y + 66, x + 54, y + 70), radius=2, fill="#8ed6ff")
    draw.line((x + 15, y + 39, x + 28, y + 30, x + 40, y + 34, x + 54, y + 18), fill="#3ce0e6", width=4)
    draw.line((x + 17, y + 45, x + 55, y + 45), fill="#3ce0e6", width=3)


def draw_blue_card(draw: ImageDraw.ImageDraw) -> None:
    card = (642, 329, 1023, 433)
    draw.rounded_rectangle(card, radius=15, fill="#053a91", outline="#0c8ce8", width=1)
    draw.rounded_rectangle((658, 343, 754, 421), radius=9, outline="#0aa0da", width=2)
    left_icon_monitor(draw)
    centered_text(
        draw,
        (770, 350, 995, 411),
        ["运行时客户端", "Runtime Client"],
        [28, 23],
        fills=[WHITE, WHITE],
        bolds=[True, False],
        line_gap=6,
    )


def main() -> None:
    image = Image.open(SOURCE).convert("RGB")
    draw = ImageDraw.Draw(image)

    # Clear old text while preserving the generated template's decorations.
    draw.rectangle((500, 0, 1172, 95), fill=WHITE)
    draw.rectangle((650, 178, 1110, 250), fill=WHITE)
    draw.rectangle((210, 525, 525, 612), fill=WHITE)
    draw.rectangle((1240, 525, 1595, 612), fill=WHITE)
    draw.rectangle((620, 768, 1130, 842), fill=WHITE)
    draw.rectangle((740, 606, 932, 640), fill=WHITE)

    # Title.
    centered_text(
        draw,
        (500, 16, 1172, 83),
        ["客户端需求用例图"],
        [58],
        fills=[NAVY],
        bolds=[True],
    )

    # Central card.
    draw_blue_card(draw)

    # Top module.
    centered_text(
        draw,
        (650, 177, 1110, 248),
        ["接入执行接口", "Onboarding & Execution Interface"],
        [27, 21],
        fills=[NAVY, "#111827"],
        bolds=[True, False],
    )

    # Left module.
    centered_text(
        draw,
        (205, 526, 532, 611),
        ["First Registration & Activation", "激活码接入交换 / 换取长期凭据"],
        [22, 18],
        fills=[NAVY, "#111827"],
        bolds=[True, False],
        line_gap=10,
    )

    # Right module.
    centered_text(
        draw,
        (1235, 526, 1598, 611),
        ["Local Reuse & State Sync", "保存接入配置 / 复用凭据 / 同步 Runtime 状态"],
        [24, 17],
        fills=[NAVY, "#111827"],
        bolds=[True, False],
        line_gap=10,
    )

    # Bottom module.
    centered_text(
        draw,
        (615, 774, 1128, 838),
        ["Protocol Compatibility & Auto Adaptation", "HTTP / WebSocket / OpenClaw 兼容"],
        [19, 18],
        fills=[NAVY, "#111827"],
        bolds=[True, False],
        line_gap=9,
    )

    # Center actor label.
    centered_text(
        draw,
        (730, 606, 942, 638),
        ["client / Runtime 客户端"],
        [18],
        fills=[NAVY],
        bolds=[True],
    )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
