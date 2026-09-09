import pytest

from async_port_scanner.cli import (
    build_arg_parser,
    parse_ports,
    process_cli_args,
)


class TestParsePorts:
    def test_single_ports(self):
        assert list(parse_ports("80,443")) == [80, 443]

    def test_mixed_singles_and_ranges(self):
        assert list(parse_ports("20-25,53,80,111")) == [
            20,
            21,
            22,
            23,
            24,
            25,
            53,
            80,
            111,
        ]

    def test_single_range(self):
        assert list(parse_ports("1-5")) == [1, 2, 3, 4, 5]

    @pytest.mark.parametrize("invalid_port", ["0", "65536", "-1", "100000"])
    def test_out_of_range_port_exits(self, invalid_port):
        with pytest.raises(SystemExit):
            list(parse_ports(invalid_port))

    @pytest.mark.parametrize("invalid_range", ["100-50", "0-10", "60000-70000"])
    def test_invalid_range_exits(self, invalid_range):
        """Descending, zero-inclusive, and out-of-bounds ranges must
        raise rather than silently yield an empty or malformed range."""
        with pytest.raises(SystemExit):
            list(parse_ports(invalid_range))


class TestProcessCliArgs:
    def test_wires_targets_ports_and_kwargs(self):
        scanner = process_cli_args(
            targets="example.com,example.org", ports="80,443", timeout=5.0
        )
        assert scanner.targets == ("example.com", "example.org")
        assert scanner.ports == (80, 443)
        assert scanner.timeout == 5.0


class TestArgParser:
    def test_version_flag_exits_zero(self, capsys):
        parser = build_arg_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0
        assert "async-port-scanner" in capsys.readouterr().out

    def test_missing_required_ports_flag_exits_nonzero(self, capsys):
        parser = build_arg_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["example.com"])
        assert exc_info.value.code != 0

    def test_parses_expected_defaults(self):
        parser = build_arg_parser()
        args = parser.parse_args(["example.com", "-p", "80"])
        assert args.targets == "example.com"
        assert args.ports == "80"
        assert args.timeout == 10.0
        assert args.open is False

    def test_open_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["example.com", "-p", "80", "--open"])
        assert args.open is True
