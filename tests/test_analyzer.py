import pytest

from anfs.protocol.nfs3.common.factory import NFS3ConnectionFactory
from anfs.utils.analyzer import NFS3Analyzer, Coloring, JSONStatus

pytestmark = [pytest.mark.asyncio, pytest.mark.timeout(120)]

# One run of the analyzer per server, the tests look at different parts of the report.
# Nothing here writes to the servers (the no_root_squash check that does is not enabled).
_reports = {}

async def get_report(server):
	if server not in _reports:
		factory = NFS3ConnectionFactory.from_url('nfs://%s' % server)
		analyzer = NFS3Analyzer(factory, colors = Coloring(False), quiet = True)
		_reports[server] = await analyzer.run()
	return _reports[server]

def is_knfsd(report):
	return report['nfs4']['server']['major_id'] == 'knfsd'

async def test_os_guess(server):
	report = await get_report(server)
	if is_knfsd(report):
		assert report['os']['final_guess'] == 'Linux'
		assert report['os']['checks']['linux_fh_0100'] is True
	else:
		# has 32 byte NFSv3 handles like Windows
		assert report['os']['final_guess'] == 'NFS-Ganesha'
		assert report['os']['checks']['windows_fh_32'] is False
	assert report['windows_handle_signing']['reason'] == 'not_windows'

async def test_v3_access(server):
	report = await get_report(server)
	exports = report['exports']['directories']
	rw = exports['/srv/exports/rw']['access']
	assert rw['root_squash']['status'] == JSONStatus.VULNERABLE
	assert rw['uid_spoofing']['status'] == JSONStatus.VULNERABLE
	assert rw['uid_spoofing']['uid'] == 1000
	assert rw['writable']['as'] == ['root']

	ro = exports['/srv/exports/ro']['access']
	assert ro['root_squash']['status'] == JSONStatus.OK
	assert ro['uid_spoofing']['status'] == JSONStatus.VULNERABLE
	assert ro['writable']['as'] == []

	squash = exports['/srv/exports/squash']['access']
	assert squash['root_squash']['status'] == JSONStatus.OK
	assert squash['uid_spoofing']['status'] == JSONStatus.OK
	assert squash['uid_spoofing']['reason'] == 'all_squashed'

async def test_nfs4_server(server):
	report = await get_report(server)
	nfs4 = report['nfs4']
	assert nfs4['status'] == JSONStatus.OK
	assert nfs4['minor_versions'] == [0, 1, 2]
	assert nfs4['used_minor_version'] == 1
	assert nfs4['root_fh']
	if is_knfsd(report):
		assert nfs4['server']['impl_domain'] == 'kernel.org'
		assert nfs4['server']['impl_name'].startswith('Linux ')
	else:
		assert nfs4['server']['major_id'] == 'ganesha'

async def test_nfs4_exports(server):
	report = await get_report(server)
	exports = report['nfs4']['exports']
	assert exports['/']['type'] == 'root'
	for name in ('/rw', '/ro', '/squash'):
		assert exports[name]['access'] == JSONStatus.OK
		assert exports[name]['auth_methods'] == ['sys']
		assert exports[name]['file_handle']
	assert exports['/rw']['checks']['root_squash']['status'] == JSONStatus.VULNERABLE
	assert exports['/rw']['checks']['writable']['as'] == ['root']
	assert exports['/ro']['checks']['root_squash']['status'] == JSONStatus.OK
	assert exports['/ro']['checks']['writable']['as'] == []
	assert exports['/squash']['checks']['uid_spoofing']['status'] == JSONStatus.OK
	if is_knfsd(report):
		# needs a source port below 1024
		assert exports['/secure']['access'] == JSONStatus.ERROR
		assert exports['/secure']['access_error'] == 'NFS4ERR_PERM'
		# a plain directory of the root export, not an export of its own over NFSv4
		assert '/nomount' not in exports

async def test_version_differences(server):
	report = await get_report(server)
	diffs = report['version_differences']
	if not is_knfsd(report):
		assert diffs == []
		return
	# no_root_squash and rw over NFSv3, the options of the NFSv4 root (ro, root_squash) over NFSv4
	assert {d['export'] for d in diffs} == {'/srv/exports/nomount'}
	by_check = {d['check']: d for d in diffs}
	assert by_check['root_squash']['nfs3'] == 'root_not_squashed'
	assert by_check['root_squash']['nfs4'] == 'root_squashed'
	assert by_check['writable']['nfs3'] == 'root'

async def test_nfs4_only(server):
	"""Without the NFSv3 part only the NFS port is used"""
	factory = NFS3ConnectionFactory.from_url('nfs://%s' % server)
	analyzer = NFS3Analyzer(factory, colors = Coloring(False), quiet = True, check_v3 = False)
	report = await analyzer.run()
	assert report['portmap']['status'] != JSONStatus.OK
	assert report['nfs4']['status'] == JSONStatus.OK
	assert report['os']['final_guess'] in ('Linux', 'NFS-Ganesha')
