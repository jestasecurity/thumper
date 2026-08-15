from thumper.services.templates import (
    generate_value,
    get_template,
    list_templates,
    reset_cache,
)


def setup_function():
    reset_cache()


def test_list_templates_returns_all():
    templates = list_templates()
    slugs = {t["slug"] for t in templates}
    assert {"stripe", "github", "slack", "aws"} <= slugs
    assert len(templates) >= 10


def test_list_templates_sorted_by_category_then_name():
    templates = list_templates()
    categories = [t["category"] for t in templates]
    assert categories == sorted(categories)


def test_every_template_has_the_required_shape():
    for t in list_templates():
        assert t["slug"] and t["name"] and t["category"]
        assert "prefix" in t["format"] or t["format"].get("prefix", "") == ""
        assert isinstance(t["format"]["length"], int)
        assert isinstance(t["suggested_paths"], list) and t["suggested_paths"]


def test_get_template_by_slug():
    t = get_template("stripe")
    assert t is not None
    assert t["name"] == "Stripe API Key"
    assert t["category"] == "Finance"
    assert "format" in t and "suggested_paths" in t


def test_get_template_unknown_returns_none():
    assert get_template("nonexistent") is None


def test_generate_value_with_prefix_and_length():
    t = get_template("stripe")
    value = generate_value(t)
    assert value.startswith("sk_live_")
    assert len(value) == t["format"]["length"] == 48


def test_generate_value_alphanumeric():
    t = get_template("github")
    value = generate_value(t)
    assert value.startswith("ghp_")
    assert value[len("ghp_"):].isalnum()


def test_generate_value_hex():
    t = get_template("datadog")
    value = generate_value(t)
    int(value, 16)  # hex charset -> parses as hex, must not raise


def test_generate_value_uppercase():
    t = get_template("aws")
    value = generate_value(t)
    assert value.startswith("AKIA")
    suffix = value[len("AKIA"):]
    assert suffix == suffix.upper() and suffix.isalnum()


def test_generate_value_is_unique_each_call():
    t = get_template("stripe")
    assert generate_value(t) != generate_value(t)
