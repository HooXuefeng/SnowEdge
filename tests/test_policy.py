from app.policy import classify_action, is_auto_allowed, PolicyClass

def test_allowed():
    assert is_auto_allowed("http_probe")
    assert is_auto_allowed("port_scan")

def test_default_deny():
    assert classify_action("unknown_action") == PolicyClass.DESTRUCTIVE
    assert not is_auto_allowed("arbitrary_command")
    assert not is_auto_allowed("upload_file")
