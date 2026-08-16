from jarVisXstar.core.waf_engine import WAFEngine

def test_sqli():
    waf = WAFEngine()
    safe, report = waf.inspect("' OR 1=1 --", "127.0.0.1")
    assert safe is False
    assert "SQLi" in str(report["triggers"])

def test_xss():
    waf = WAFEngine()
    safe, report = waf.inspect("<script>alert(1)</script>", "127.0.0.1")
    assert safe is False
    assert "XSS" in str(report["triggers"])