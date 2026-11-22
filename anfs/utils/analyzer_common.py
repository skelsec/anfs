#!/usr/bin/env python3
#
# Helpers shared by the NFSv3 and the NFSv4 part of the security analyzer.
from anfs.protocol.rpc.messages import AUTH_SYS


class JSONStatus:
	OK = "ok"
	SKIPPED = "skipped"
	UNKNOWN = "unknown"
	ERROR = "error"
	VULNERABLE = "vulnerable"


AUTH_FLAVOR_NAMES = {
	0: "none",
	1: "sys",
	3: "dh",
	390003: "krb5",
	390004: "krb5i",
	390005: "krb5p",
}



def auth_flavor_to_str(flavor):
	return AUTH_FLAVOR_NAMES.get(flavor, str(flavor))


# --------------------------------------------------------------------------- #
# Colored / plain output helpers
# --------------------------------------------------------------------------- #
class Coloring:
	def __init__(self, enabled=True):
		self.enabled = enabled
		self.OK = ""
		self.WARN = ""
		self.ERROR = ""
		self.RESET = ""
		if enabled:
			try:
				import colorama
				colorama.just_fix_windows_console()
				self.OK = colorama.Fore.GREEN
				self.WARN = colorama.Fore.YELLOW
				self.ERROR = colorama.Fore.RED
				self.RESET = colorama.Style.RESET_ALL
			except Exception:
				self.enabled = False

	def _wrap(self, text, color):
		if not self.enabled:
			return text
		return "%s%s%s" % (color, text, self.RESET)

	def ok(self, text):
		return self._wrap(text, self.OK)

	def warn(self, text):
		return self._wrap(text, self.WARN)

	def error(self, text):
		return self._wrap(text, self.ERROR)


def printable_len(string):
	length = 0
	escape_sequence = False
	for c in string:
		if not escape_sequence:
			if c == "\033":
				escape_sequence = True
			else:
				length += 1
		else:
			if c == "m":
				escape_sequence = False
	return length


def format_table(rows):
	if len(rows) <= 1:
		return "[empty]"
	columns = len(rows[0])
	max_lens = [0] * columns
	for row in rows:
		for i in range(columns):
			max_lens[i] = max(max_lens[i], printable_len(str(row[i])))
	lines = []
	for row in rows:
		parts = []
		for i in range(columns):
			cell = str(row[i])
			parts.append(cell + " " * (max_lens[i] - printable_len(cell)))
		lines.append(" ".join(parts).rstrip())
	return "\n".join(lines)


def make_cred(uid, gid, gids=None, machinename="anfs", stamp=None):
	if gids is None:
		gids = [gid]
	return AUTH_SYS(uid=uid, gid=gid, gids=gids, machinename=machinename, stamp=stamp)
