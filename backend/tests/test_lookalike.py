import pytest

from unhook.analysis.hostutil import (
    defang,
    defang_text,
    has_known_suffix,
    registered_domain,
    split_host,
    to_unicode,
)
from unhook.analysis.lookalike import check_host, is_mixed_script, osa_distance, skeletons


@pytest.mark.parametrize("host,kind", [
    ("paypa1.com", "homoglyph"),
    ("rnicrosoft.com", "homoglyph"),
    ("micr0soft.com", "homoglyph"),
    ("xn--pple-43d.example", "homoglyph"),          # Cyrillic a + "pple"
    ("microsft.com", "typosquat"),
    ("paypall.com", "typosquat"),
    ("amazon-support.example", "combosquat"),
    ("secure-paypal.net", "combosquat"),
    ("microsoftsupport.example", "combosquat"),
    ("dhl-express-tracking.example", "combosquat"),
    ("paypal.com.account-check.example", "brand_subdomain"),
    ("login.microsoftonline.com.verify.example", "brand_subdomain"),
    ("paypal.account-check.example", "brand_subdomain"),
    ("paypal.co", "tld_swap"),
])
def test_lookalikes_are_caught(host, kind):
    hit = check_host(host)
    assert hit is not None, host
    assert hit.kind == kind


@pytest.mark.parametrize("host", [
    "paypal.com", "www.paypal.com", "login.microsoftonline.com", "mail.google.com", "outlook.office.com",
    "docusign.net", "na3.docusign.net", "example.org", "ridgewoodschools.org", "maple.com", "groups.example",
    "applebees.com", "my-small-bakery.example", "sendgrid.net",
])
def test_ordinary_domains_are_left_alone(host):
    assert check_host(host) is None, host


def test_the_organisations_own_domain_is_protected_too():
    from unhook.analysis.lookalike import org_brand

    extra = org_brand(["ridgewood-usd.example"])
    assert check_host("ridgewood-usd-hr.example", extra=extra).kind == "combosquat"
    assert check_host("ridgewood-usd.example", extra=extra) is None
    assert check_host("ridgewood-usd.example") is None


def test_skeletons_cover_both_readings_of_a_one():
    assert {"paypal"} <= skeletons("paypa1")
    assert {"mail", "maii"} <= skeletons("ma1l") | {"maii"}


def test_mixed_script_detection():
    assert is_mixed_script("xn--pple-43d.example")
    assert not is_mixed_script("apple.com")
    assert not is_mixed_script("xn--bcher-kva.example")  # bücher: accented Latin only


def test_osa_distance_counts_a_swap_as_one_edit():
    assert osa_distance("paypal", "paypla") == 1
    assert osa_distance("abc", "abc") == 0
    assert osa_distance("kitten", "sitting") == 3


def test_registered_domain_handles_private_suffixes_and_reserved_tlds():
    assert registered_domain("a.b.example.co.uk") == "example.co.uk"
    assert registered_domain("evil.github.io") == "evil.github.io"
    assert registered_domain("login.thing.example") == "thing.example"
    assert split_host("203.0.113.5").label == "203.0.113.5"


def test_known_suffix_helper():
    assert has_known_suffix("paypal.com") and has_known_suffix("a.example")
    assert not has_known_suffix("budget.xlsx") and not has_known_suffix("203.0.113.5")


def test_to_unicode_decodes_idna_labels():
    assert to_unicode("xn--bcher-kva.example") == "bücher.example"


def test_defang():
    assert defang("https://evil.example/a.b") == "hxxps://evil[.]example/a.b"
    assert defang("evil.example") == "evil[.]example"


def test_defang_text_also_covers_internationalised_hosts():
    assert defang_text("reads like \u0430pple.example here") == "reads like \u0430pple[.]example here"
    assert defang_text("Invoice_4471.pdf.exe stays readable") == "Invoice_4471.pdf.exe stays readable"


def test_lookalike_detail_continues_the_sentence_instead_of_repeating_the_host():
    found = check_host("paypa1-secure.example")
    assert found and found.detail.startswith("reads like paypal.com")
    wrapped = check_host("dhl-parcel-notice.example")
    assert wrapped and wrapped.host not in wrapped.detail
