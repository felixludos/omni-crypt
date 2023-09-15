
from . import secure as scr
from omnibelt import adict, tdict, tlist, tset



def _get_adict():
	x = adict()
	x.a = 1
	x.x = x
	x.l = [tlist(), tset()]
	x[100] = '100'
	x[None] = 1.2
	x.m = None
	x[True] = tlist
	x[list] = complex
	x['<>)dksfl_ ds: gkal'] = '<>1234543224'
	x['d = ds=a _+ sd;'] = bytes(range(256))
	x[12.2344+.023j] = range(123,456,7)
	# np.random.seed(1)
	# x.b = np.random.randn(3).tobytes()
	x[b'\xaa'] = 'running'
	return x



def test_format_key():
	hash = 'test'
	b = scr.format_key(hash)
	assert scr.format_key(hash) == scr.format_key(hash)
	assert len(b) == 44



def test_format_key_no_change():
	hash = 'test'
	ans = b'T0vazoLj6Q1tMpVbHkZLFTUi-V0dCzVaE7VHdSoZYOE='
	b = scr.format_key(hash)
	assert b == ans



def test_secure_key():
	data = 'test'
	salt = scr.generate_salt()

	assert scr.secure_key(data, salt) == scr.secure_key(data, salt)
	assert scr.secure_key(data) != scr.secure_key(data, salt)
	assert scr.secure_key(data) == scr.secure_key(data) # using default master salt



def test_secure_key_no_change():
	hash = 'test'
	ans = '$2b$12$hLpFQgUWLNQgO0dE8sbN3e7c2.Ov2wtwpBnEXT9bFWXx24.POLs5G'
	salt = b'$2b$12$hLpFQgUWLNQgO0dE8sbN3e'
	assert scr.secure_key(hash, salt) == ans



def test_encryption():
	data = b'aslkjqtest_encryption()2\4awsef'
	hsh = 'test'
	
	x = scr.encrypt(data, hsh)
	rec = scr.decrypt(x, hsh)
	
	assert data == rec
	


def test_secure_pack():
	hsh = 'test'
	
	data = _get_adict()
	b = scr.secure_pack(data, hsh=hsh)
	rec = scr.secure_unpack(b, hsh=hsh)
	
	assert repr(data) == repr(rec)
	
