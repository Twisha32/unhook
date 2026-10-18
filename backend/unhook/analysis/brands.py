"""Brands that phishers like to borrow.

`keywords` are what a human would write in a subject or body. `domains` are the
registered domains the brand legitimately sends mail and hosts login pages from.
The list is deliberately biased toward what schools, clinics, nonprofits and city
offices actually see: Microsoft/Google logins, payroll, shipping, tax, banks.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    keywords: tuple[str, ...]
    domains: tuple[str, ...]

    @property
    def labels(self) -> set[str]:
        return {d.split(".")[0] for d in self.domains}


def _b(name, keywords, *domains):
    return Brand(name, tuple(keywords), tuple(domains))


BRANDS: list[Brand] = [
    _b("Microsoft", ["microsoft", "office 365", "office365", "microsoft 365", "outlook", "sharepoint", "onedrive", "microsoft teams"],
       "microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "microsoftonline.com",
       "sharepoint.com", "onedrive.com", "windows.com", "microsoft365.com", "outlook.office.com", "msn.com"),
    _b("Google", ["google", "gmail", "google drive", "google docs", "google workspace", "google classroom"],
       "google.com", "gmail.com", "googlemail.com", "google.org", "withgoogle.com", "youtube.com", "g.co", "goo.gl", "forms.gle"),
    _b("Apple", ["apple id", "icloud", "apple"], "apple.com", "icloud.com", "me.com"),
    _b("Amazon", ["amazon", "amazon prime", "aws"], "amazon.com", "amazon.ca", "amazon.co.uk", "amazon.de", "amazon.in", "amazonaws.com", "amazonses.com"),
    _b("PayPal", ["paypal"], "paypal.com", "paypal.me", "paypalobjects.com", "paypal-communications.com"),
    _b("DocuSign", ["docusign"], "docusign.com", "docusign.net"),
    _b("Dropbox", ["dropbox"], "dropbox.com", "dropboxmail.com"),
    _b("Adobe", ["adobe", "adobe sign", "acrobat"], "adobe.com", "adobesign.com", "echosign.com"),
    _b("LinkedIn", ["linkedin"], "linkedin.com", "licdn.com"),
    _b("Meta", ["facebook", "instagram", "whatsapp"], "facebook.com", "facebookmail.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com"),
    _b("Netflix", ["netflix"], "netflix.com"),
    _b("DHL", ["dhl"], "dhl.com", "dhl.de"),
    _b("FedEx", ["fedex"], "fedex.com"),
    _b("UPS", ["ups"], "ups.com"),
    _b("USPS", ["usps", "postal service"], "usps.com", "usps.gov"),
    _b("IRS", ["irs", "internal revenue service"], "irs.gov"),
    _b("Social Security", ["social security"], "ssa.gov"),
    _b("Chase", ["chase", "jpmorgan"], "chase.com", "jpmorgan.com", "jpmorganchase.com"),
    _b("Wells Fargo", ["wells fargo"], "wellsfargo.com", "wf.com"),
    _b("Bank of America", ["bank of america"], "bankofamerica.com", "bofa.com"),
    _b("Citi", ["citibank", "citi"], "citi.com", "citibank.com"),
    _b("Capital One", ["capital one"], "capitalone.com"),
    _b("American Express", ["american express", "amex"], "americanexpress.com", "aexp.com"),
    _b("Mastercard", ["mastercard"], "mastercard.com"),
    _b("Visa", ["visa"], "visa.com"),
    _b("Zelle", ["zelle"], "zellepay.com", "zelle.com"),
    _b("Venmo", ["venmo"], "venmo.com"),
    _b("Cash App", ["cash app"], "cash.app", "squareup.com"),
    _b("Coinbase", ["coinbase"], "coinbase.com"),
    _b("Binance", ["binance"], "binance.com"),
    _b("Zoom", ["zoom"], "zoom.us", "zoom.com"),
    _b("Slack", ["slack"], "slack.com"),
    _b("Okta", ["okta"], "okta.com", "oktapreview.com"),
    _b("Duo", ["duo security", "duo mobile"], "duo.com", "duosecurity.com"),
    _b("GitHub", ["github"], "github.com"),
    _b("Workday", ["workday"], "workday.com", "myworkday.com"),
    _b("ADP", ["adp"], "adp.com"),
    _b("Intuit", ["quickbooks", "turbotax", "intuit"], "intuit.com", "quickbooks.com", "turbotax.com"),
    _b("Salesforce", ["salesforce"], "salesforce.com", "force.com"),
    _b("Box", ["box"], "box.com"),
    _b("WeTransfer", ["wetransfer"], "wetransfer.com", "we.tl"),
    _b("Canvas", ["canvas", "instructure"], "instructure.com", "canvaslms.com"),
    _b("PowerSchool", ["powerschool"], "powerschool.com"),
    _b("Blackboard", ["blackboard"], "blackboard.com", "anthology.com"),
    _b("ClassLink", ["classlink"], "classlink.com"),
    _b("Clever", ["clever"], "clever.com"),
    _b("MyChart", ["mychart"], "mychart.com", "epic.com"),
    _b("UnitedHealthcare", ["unitedhealthcare", "united healthcare"], "uhc.com", "unitedhealthcare.com"),
    _b("Medicare", ["medicare"], "medicare.gov", "cms.gov"),
]

# Words attackers bolt onto a brand name: paypal-secure.com, microsoft-support.net
LURE_WORDS = {
    "secure", "security", "support", "login", "signin", "verify", "verification", "account", "accounts",
    "billing", "service", "services", "helpdesk", "update", "alert", "alerts", "auth", "online", "portal",
    "mail", "team", "care", "pay", "payment", "wallet", "notice", "confirm", "recovery", "unlock",
    "resolution", "center", "centre", "id", "access", "client", "customer", "my", "web", "app",
}

# Big shared platforms. Blocking the registered domain would break the internet,
# so anything hosted here is indicated by full URL only.
SHARED_PLATFORMS = {
    "google.com", "googleusercontent.com", "forms.gle", "goo.gl", "sharepoint.com", "onedrive.com",
    "live.com", "microsoft.com", "dropbox.com", "box.com", "notion.so", "notion.site", "canva.com",
    "typeform.com", "docs.google.com", "amazonaws.com", "github.com", "githubusercontent.com",
    "linkedin.com", "facebook.com", "wetransfer.com", "we.tl", "bit.ly", "t.co", "tinyurl.com",
    "sendgrid.net", "mailchimp.com", "list-manage.com", "hubspot.com", "constantcontact.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "tiny.cc", "shorturl.at", "rb.gy", "t.ly", "lnkd.in", "s.id", "qrco.de", "bl.ink", "short.io",
}

# Hosting that costs nothing and takes minutes to set up. Weak signal on its own.
FREE_HOSTING_SUFFIXES = (
    "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "netlify.app", "vercel.app", "github.io",
    "glitch.me", "weebly.com", "wixsite.com", "blogspot.com", "000webhostapp.com", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com", "r2.dev", "web.core.windows.net", "herokuapp.com",
    "repl.co", "framer.website", "carrd.co", "square.site", "godaddysites.com", "weeblysite.com",
)

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "support", "rest", "cfd", "sbs"}

FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "ymail.com",
    "aol.com", "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com",
    "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "qq.com", "163.com", "msn.com", "comcast.net", "att.net",
}
