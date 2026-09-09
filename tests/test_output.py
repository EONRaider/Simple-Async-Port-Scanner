from async_port_scanner.output import OutputToScreen


class _FakeScanner:
    def __init__(
        self,
        results,
        targets=("example.com",),
        ports=(80,),
        total_time=0.12,
    ):
        self.results = results
        self.targets = targets
        self.ports = ports
        self.total_time = total_time

    def register(self, observer):
        pass


async def test_prints_all_results_by_default(capsys):
    fake = _FakeScanner(
        results={
            "example.com": {
                80: ("open", "http", "SYN/ACK"),
                22: ("closed", "ssh", "Connection refused"),
            }
        },
        ports=(22, 80),
    )
    out = OutputToScreen(subject=fake, show_open_only=False)
    await out.update()

    captured = capsys.readouterr().out
    assert "80" in captured
    assert "22" in captured
    assert "open" in captured
    assert "closed" in captured


async def test_open_only_filters_out_closed_ports(capsys):
    fake = _FakeScanner(
        results={
            "example.com": {
                80: ("open", "http", "SYN/ACK"),
                22: ("closed", "ssh", "Connection refused"),
            }
        },
        ports=(22, 80),
    )
    out = OutputToScreen(subject=fake, show_open_only=True)
    await out.update()

    captured = capsys.readouterr().out
    assert "80" in captured
    assert "22" not in captured


async def test_summary_line_reports_total_ports_and_time(capsys):
    fake = _FakeScanner(
        results={"example.com": {80: ("open", "http", "SYN/ACK")}},
        targets=("example.com",),
        ports=(80,),
        total_time=1.23,
    )
    out = OutputToScreen(subject=fake, show_open_only=False)
    await out.update()

    captured = capsys.readouterr().out
    assert "1 ports" in captured
    assert "1.23 seconds" in captured
