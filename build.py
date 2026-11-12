from pathlib import Path
from shutil import copy, rmtree

from markdown import Markdown

ROOT = Path(__file__).parent
OUTPUT = ROOT / "public"
TEMPLATE = (ROOT / "template.html").read_text()
EXTENSIONS = ["meta", "fenced_code", "codehilite", "tables", "footnotes"]
EXTENSION_CONFIGS = {"codehilite": {"guess_lang": False}}


def render(path):
    parser = Markdown(extensions=EXTENSIONS, extension_configs=EXTENSION_CONFIGS)
    html = parser.convert(path.read_text())
    meta = {key: values[0] for key, values in parser.Meta.items()}
    return meta, html


def write_page(name, title, content):
    (OUTPUT / name).write_text(TEMPLATE.format(title=title, content=content))


def build_posts():
    posts = []
    for path in (ROOT / "posts").glob("*.md"):
        meta, html = render(path)
        post = {"url": f"{path.stem}.html", "title": meta["title"], "date": meta["date"]}
        header = f'<h1>{post["title"]}</h1><time>{post["date"]}</time>'
        write_page(post["url"], post["title"], f"<article>{header}{html}</article>")
        posts.append(post)
    return sorted(posts, key=lambda post: post["date"], reverse=True)


def build_index(posts):
    rows = "".join(
        f'<li><time>{post["date"]}</time><a href="{post["url"]}">{post["title"]}</a></li>'
        for post in posts
    )
    content = f'<ul class="posts">{rows}</ul>' if posts else "<p>No posts yet.</p>"
    write_page("index.html", "posts", content)


def build_about():
    meta, html = render(ROOT / "about.md")
    write_page("about.html", meta["title"], f"<article>{html}</article>")


def main():
    rmtree(OUTPUT, ignore_errors=True)
    OUTPUT.mkdir()
    copy(ROOT / "style.css", OUTPUT)
    copy(ROOT / "avatar.png", OUTPUT)
    build_index(build_posts())
    build_about()


if __name__ == "__main__":
    main()
